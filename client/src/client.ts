import type {
  WireItem,
  PushItem,
  PushRequest,
  PushResponse,
  PullResponse,
  RecipientPolicyResponse,
  VersionsRequest,
  VersionsResponse,
  DeleteRequest,
  DeleteResponse,
  Kind,
} from "./types.generated.js";
import {
  MAX_HOSTED_ENVELOPE_BYTES,
  MAX_HOSTED_PULL_RESPONSE_BYTES,
  MAX_HOSTED_SYNC_BODY_BYTES,
} from "./limits.js";

export interface NvaultClientOptions {
  /** Base URL of the nvault-cloud HTTP deployment. */
  baseUrl: string;
  /** Organization id (Convex document id). */
  org: string;
  /** Environment id (Convex document id). */
  env: string;
  /** Service token (nvk_…). Sent as Authorization: Bearer. */
  token: string;
  /** Logical scope within the environment. Defaults to global. */
  scope?: string;
  /** Permit cleartext HTTP for a non-local endpoint. Default: false. */
  allowInsecureHttp?: boolean;
  /** Optional fetch override for tests or runtimes without global fetch. */
  fetch?: typeof fetch;
}

export interface PullPageOptions {
  cursor?: string | null;
  limit?: number;
}

export interface PushOptions {
  /** Recipient generation returned by the latest pull or authenticated UI. */
  recipientRevision: number;
}

export class NvaultError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "NvaultError";
  }
}

const MAX_PULL_PAGE_ITEMS = 10;
const MAX_PUSH_ITEMS = 100;
const MAX_ERROR_RESPONSE_BYTES = 8 << 10;
const MAX_POLICY_RESPONSE_BYTES = 1 << 20;
const MAX_PULL_ITEMS = 10_000;
const MAX_PULL_PAGES = 1_001;
const MAX_PULL_CIPHERTEXT_BYTES = 256 << 20;
const TOKEN = /^nvk_[A-Za-z0-9_-]{43}$/;
const IDENTIFIER = /^[A-Za-z0-9_-]+$/;
const SCOPE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const ITEM_KEY = /^[A-Za-z_][A-Za-z0-9_.-]*$/;
const PUBLIC_KEY = /^nvpub_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

function sanitizeErrorDetail(value: string): string {
  return value
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

function assertIdentifier(value: string, name: string): void {
  if (value.length < 10 || value.length > 128 || !IDENTIFIER.test(value)) {
    throw new NvaultError(`${name} is invalid`);
  }
}

function normalizeBaseURL(value: string, allowInsecureHttp: boolean): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new NvaultError("baseUrl is invalid");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new NvaultError(
      "baseUrl must not contain credentials, a query, or a fragment",
    );
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new NvaultError("baseUrl must use HTTPS or HTTP");
  }
  const local =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "::1";
  if (url.protocol !== "https:" && !local && !allowInsecureHttp) {
    throw new NvaultError("baseUrl must use HTTPS outside local development");
  }
  return url.toString().replace(/\/$/, "");
}

async function readBounded(
  response: Response,
  maximum: number,
): Promise<string> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const declared = Number(contentLength);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > maximum) {
      throw new NvaultError("server response exceeds its size limit");
    }
  }
  if (!response.body) {
    const text = await response.text();
    if (byteLength(text) > maximum) {
      throw new NvaultError("server response exceeds its size limit");
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maximum) {
      await reader.cancel();
      throw new NvaultError("server response exceeds its size limit");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new NvaultError("server response is not valid UTF-8");
  }
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseWireItem(value: unknown, index: number): WireItem {
  const item = object(value);
  if (
    !item ||
    typeof item.key !== "string" ||
    byteLength(item.key) > 256 ||
    !ITEM_KEY.test(item.key) ||
    (item.kind !== "secret" && item.kind !== "param") ||
    typeof item.ciphertext !== "string" ||
    !Number.isSafeInteger(item.version) ||
    (item.version as number) < 1
  ) {
    throw new NvaultError(`server returned an invalid item at index ${index}`);
  }
  if (byteLength(item.ciphertext) > MAX_HOSTED_ENVELOPE_BYTES) {
    throw new NvaultError(`server item ${index} exceeds its size limit`);
  }
  return {
    key: item.key,
    kind: item.kind,
    ciphertext: item.ciphertext,
    version: item.version as number,
  };
}

function parsePullResponse(value: unknown, limit: number): PullResponse {
  const response = object(value);
  if (
    !response ||
    !Array.isArray(response.items) ||
    response.items.length > limit ||
    !Number.isSafeInteger(response.recipient_revision) ||
    (response.recipient_revision as number) < 1 ||
    (response.cursor !== null && typeof response.cursor !== "string") ||
    typeof response.done !== "boolean" ||
    (response.done && response.cursor !== null) ||
    (!response.done &&
      (typeof response.cursor !== "string" ||
        response.cursor.length < 1 ||
        response.cursor.length > 4096))
  ) {
    throw new NvaultError("server returned an invalid pull response");
  }
  return {
    items: response.items.map(parseWireItem),
    recipient_revision: response.recipient_revision as number,
    cursor: response.cursor,
    done: response.done,
  };
}

function parsePushResponse(
  value: unknown,
  expectedItems: readonly PushItem[],
): PushResponse {
  const response = object(value);
  if (
    !response ||
    !Array.isArray(response.results) ||
    response.results.length !== expectedItems.length
  ) {
    throw new NvaultError("server returned an invalid push response");
  }
  const results = response.results.map((value, index) => {
    const result = object(value);
    if (
      !result ||
      typeof result.key !== "string" ||
      result.key !== expectedItems[index].key ||
      !Number.isSafeInteger(result.version) ||
      result.version !== expectedItems[index].expected_version + 1
    ) {
      throw new NvaultError(
        `server returned an invalid push result at index ${index}`,
      );
    }
    return { key: result.key, version: result.version as number };
  });
  return { results };
}

function parseRecipientPolicy(value: unknown): RecipientPolicyResponse {
  const response = object(value);
  if (
    !response ||
    !Number.isSafeInteger(response.recipient_revision) ||
    (response.recipient_revision as number) < 1 ||
    !Array.isArray(response.recipients) ||
    response.recipients.length < 1 ||
    response.recipients.length > 1024
  ) {
    throw new NvaultError("server returned an invalid recipient policy");
  }
  const ids = new Set<string>();
  const publicKeys = new Set<string>();
  const recipients = response.recipients.map((value, index) => {
    const recipient = object(value);
    if (
      !recipient ||
      typeof recipient.id !== "string" ||
      byteLength(recipient.id) < 1 ||
      byteLength(recipient.id) > 256 ||
      typeof recipient.public_key !== "string" ||
      !PUBLIC_KEY.test(recipient.public_key) ||
      recipient.public_key === `nvpub_${"A".repeat(43)}` ||
      (recipient.id !==
        `member-${recipient.public_key.slice("nvpub_".length)}` &&
        recipient.id !==
          `org-recovery-${recipient.public_key.slice("nvpub_".length)}`) ||
      ids.has(recipient.id) ||
      publicKeys.has(recipient.public_key)
    ) {
      throw new NvaultError(
        `server returned an invalid recipient at index ${index}`,
      );
    }
    ids.add(recipient.id);
    publicKeys.add(recipient.public_key);
    return { id: recipient.id, public_key: recipient.public_key };
  });
  return {
    recipient_revision: response.recipient_revision as number,
    recipients,
  };
}

function parseVersionsResponse(
  value: unknown,
  expectedKeys: readonly string[],
): VersionsResponse {
  const response = object(value);
  if (
    !response ||
    !Array.isArray(response.results) ||
    response.results.length !== expectedKeys.length
  ) {
    throw new NvaultError("server returned an invalid versions response");
  }
  return {
    results: response.results.map((value, index) => {
      const result = object(value);
      if (
        !result ||
        result.key !== expectedKeys[index] ||
        !Number.isSafeInteger(result.version) ||
        (result.version as number) < 0 ||
        typeof result.deleted !== "boolean" ||
        ((result.version as number) === 0 && result.deleted)
      ) {
        throw new NvaultError(
          `server returned an invalid version result at index ${index}`,
        );
      }
      return {
        key: result.key as string,
        version: result.version as number,
        deleted: result.deleted,
      };
    }),
  };
}

function parseDeleteResponse(
  value: unknown,
  expectedKey: string,
  expectedVersion: number,
): DeleteResponse {
  const response = object(value);
  if (
    !response ||
    response.key !== expectedKey ||
    !Number.isSafeInteger(response.version) ||
    (response.version as number) < expectedVersion ||
    (response.version as number) > expectedVersion + 1 ||
    response.deleted !== true
  ) {
    throw new NvaultError("server returned an invalid delete response");
  }
  return {
    key: response.key as string,
    version: response.version as number,
    deleted: true,
  };
}

/**
 * NvaultClient transports ciphertext for the managed tier. It never receives
 * plaintext. Pair it with the crypto helpers to seal and open envelopes on the
 * client.
 */
export class NvaultClient {
  private readonly opts: Readonly<NvaultClientOptions>;
  private readonly doFetch: typeof fetch;

  constructor(opts: NvaultClientOptions) {
    assertIdentifier(opts.org, "org");
    assertIdentifier(opts.env, "env");
    if (!TOKEN.test(opts.token)) throw new NvaultError("token is invalid");
    const scope = opts.scope ?? "global";
    if (byteLength(scope) > 120 || !SCOPE.test(scope)) {
      throw new NvaultError("scope is invalid");
    }
    this.doFetch = opts.fetch ?? globalThis.fetch;
    if (!this.doFetch) {
      throw new NvaultError(
        "no fetch implementation is available; pass opts.fetch",
      );
    }
    this.opts = Object.freeze({
      ...opts,
      baseUrl: normalizeBaseURL(opts.baseUrl, opts.allowInsecureHttp === true),
      scope,
    });
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.opts.token}`,
      "Content-Type": "application/json",
    };
  }

  private scope(): string {
    return this.opts.scope ?? "global";
  }

  private async responseJSON(
    response: Response,
    maximum: number,
    operation: string,
  ): Promise<unknown> {
    if (!response.ok) {
      let detail = "";
      try {
        detail = sanitizeErrorDetail(
          await readBounded(response, MAX_ERROR_RESPONSE_BYTES),
        );
      } catch {
        detail = "bounded error response unavailable";
      }
      throw new NvaultError(
        `${operation} failed: ${detail || `HTTP ${response.status}`}`,
        response.status,
      );
    }
    const text = await readBounded(response, maximum);
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new NvaultError(`server returned invalid JSON for ${operation}`);
    }
  }

  /** Fetch the current public encryption recipients and generation. */
  async policy(): Promise<RecipientPolicyResponse> {
    const query = new URLSearchParams({
      org: this.opts.org,
      env: this.opts.env,
    });
    const response = await this.doFetch(
      `${this.opts.baseUrl}/sync/policy?${query.toString()}`,
      { method: "GET", headers: this.headers(), redirect: "error" },
    );
    return parseRecipientPolicy(
      await this.responseJSON(
        response,
        MAX_POLICY_RESPONSE_BYTES,
        "recipient policy",
      ),
    );
  }

  /** Return compare-and-swap state for one bounded key set. */
  async versions(keys: readonly string[]): Promise<VersionsResponse> {
    if (keys.length < 1 || keys.length > MAX_PUSH_ITEMS) {
      throw new NvaultError(
        `versions must contain between 1 and ${MAX_PUSH_ITEMS} keys`,
      );
    }
    const seen = new Set<string>();
    const validated = keys.map((key, index) => {
      if (
        typeof key !== "string" ||
        byteLength(key) > 256 ||
        !ITEM_KEY.test(key)
      ) {
        throw new NvaultError(`versions key ${index} is invalid`);
      }
      if (seen.has(key)) {
        throw new NvaultError(`versions contains duplicate key ${key}`);
      }
      seen.add(key);
      return key;
    });
    const request: VersionsRequest = {
      org: this.opts.org,
      env: this.opts.env,
      scope: this.scope(),
      keys: validated,
    };
    const response = await this.doFetch(`${this.opts.baseUrl}/sync/versions`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(request),
      redirect: "error",
    });
    return parseVersionsResponse(
      await this.responseJSON(response, 1 << 20, "versions"),
      validated,
    );
  }

  /** Download one bounded ciphertext page. */
  async pullPage(options: PullPageOptions = {}): Promise<PullResponse> {
    const limit = options.limit ?? MAX_PULL_PAGE_ITEMS;
    if (
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > MAX_PULL_PAGE_ITEMS
    ) {
      throw new NvaultError(
        `pull limit must be an integer between 1 and ${MAX_PULL_PAGE_ITEMS}`,
      );
    }
    if (
      options.cursor !== undefined &&
      options.cursor !== null &&
      (options.cursor.length < 1 || options.cursor.length > 4096)
    ) {
      throw new NvaultError("pull cursor is invalid");
    }
    const query = new URLSearchParams({
      org: this.opts.org,
      env: this.opts.env,
      scope: this.scope(),
      limit: String(limit),
    });
    if (options.cursor) query.set("cursor", options.cursor);
    const response = await this.doFetch(
      `${this.opts.baseUrl}/sync/pull?${query.toString()}`,
      { method: "GET", headers: this.headers(), redirect: "error" },
    );
    return parsePullResponse(
      await this.responseJSON(response, MAX_HOSTED_PULL_RESPONSE_BYTES, "pull"),
      limit,
    );
  }

  /** Download every ciphertext item by following bounded server pages. */
  async pull(): Promise<WireItem[]> {
    const items: WireItem[] = [];
    const seenCursors = new Set<string>();
    const seenKeys = new Set<string>();
    let cursor: string | null = null;
    let recipientRevision: number | null = null;
    let ciphertextBytes = 0;
    for (let pageNumber = 0; pageNumber < MAX_PULL_PAGES; pageNumber += 1) {
      const page = await this.pullPage({ cursor });
      if (recipientRevision === null) {
        recipientRevision = page.recipient_revision;
      } else if (recipientRevision !== page.recipient_revision) {
        throw new NvaultError("recipient policy changed during pull; retry");
      }
      if (items.length + page.items.length > MAX_PULL_ITEMS) {
        throw new NvaultError(
          `pull exceeds the ${MAX_PULL_ITEMS}-item safety limit`,
        );
      }
      for (const item of page.items) {
        if (seenKeys.has(item.key)) {
          throw new NvaultError(`server returned duplicate key ${item.key}`);
        }
        seenKeys.add(item.key);
        ciphertextBytes += byteLength(item.ciphertext);
        if (ciphertextBytes > MAX_PULL_CIPHERTEXT_BYTES) {
          throw new NvaultError("pull exceeds its total size safety limit");
        }
        items.push(item);
      }
      if (page.done) return items;
      if (!page.cursor || seenCursors.has(page.cursor)) {
        throw new NvaultError("server returned a repeated pull cursor");
      }
      seenCursors.add(page.cursor);
      cursor = page.cursor;
    }
    throw new NvaultError("pull exceeds its page safety limit");
  }

  /** Upload one bounded ciphertext batch in one server transaction. */
  async push(items: PushItem[], options: PushOptions): Promise<PushResponse> {
    if (items.length < 1 || items.length > MAX_PUSH_ITEMS) {
      throw new NvaultError(
        `push must contain between 1 and ${MAX_PUSH_ITEMS} items`,
      );
    }
    if (
      !options ||
      !Number.isSafeInteger(options.recipientRevision) ||
      options.recipientRevision < 1
    ) {
      throw new NvaultError("recipientRevision must be a positive integer");
    }
    const seen = new Set<string>();
    const outbound = items.map((item, index): PushItem => {
      if (
        typeof item.key !== "string" ||
        byteLength(item.key) > 256 ||
        !ITEM_KEY.test(item.key) ||
        (item.kind !== "secret" && item.kind !== "param") ||
        typeof item.ciphertext !== "string" ||
        byteLength(item.ciphertext) > MAX_HOSTED_ENVELOPE_BYTES ||
        !Number.isSafeInteger(item.expected_version) ||
        item.expected_version < 0
      ) {
        throw new NvaultError(`push item ${index} is invalid`);
      }
      if (seen.has(item.key)) {
        throw new NvaultError(`push contains duplicate key ${item.key}`);
      }
      seen.add(item.key);
      return {
        key: item.key,
        kind: item.kind,
        ciphertext: item.ciphertext,
        expected_version: item.expected_version,
      };
    });
    const request: PushRequest = {
      org: this.opts.org,
      env: this.opts.env,
      scope: this.scope(),
      recipient_revision: options.recipientRevision,
      items: outbound,
    };
    const body = JSON.stringify(request);
    if (byteLength(body) > MAX_HOSTED_SYNC_BODY_BYTES) {
      throw new NvaultError("push request exceeds its size limit");
    }
    const response = await this.doFetch(`${this.opts.baseUrl}/sync/push`, {
      method: "POST",
      headers: this.headers(),
      body,
      redirect: "error",
    });
    return parsePushResponse(
      await this.responseJSON(response, 1 << 20, "push"),
      outbound,
    );
  }

  /** Create one compare-and-swap tombstone for a remote item. */
  async delete(key: string, expectedVersion: number): Promise<DeleteResponse> {
    if (byteLength(key) > 256 || !ITEM_KEY.test(key)) {
      throw new NvaultError("delete key is invalid");
    }
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) {
      throw new NvaultError("expectedVersion must be a non-negative integer");
    }
    const request: DeleteRequest = {
      org: this.opts.org,
      env: this.opts.env,
      scope: this.scope(),
      key,
      expected_version: expectedVersion,
    };
    const response = await this.doFetch(`${this.opts.baseUrl}/sync/delete`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(request),
      redirect: "error",
    });
    return parseDeleteResponse(
      await this.responseJSON(response, 1 << 20, "delete"),
      key,
      expectedVersion,
    );
  }
}

export type { DeleteResponse, Kind, PushItem, VersionsResponse, WireItem };
