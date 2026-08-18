import type {
  WireItem,
  PushRequest,
  PushResponse,
  PullResponse,
  Kind,
} from "./types.generated.js";

export interface NvaultClientOptions {
  /** Base URL of the nvault-cloud Convex HTTP deployment (…/sync lives here). */
  baseUrl: string;
  /** Org id (Convex document id). */
  org: string;
  /** Environment id (Convex document id). */
  env: string;
  /** Service token (nvk_…). Sent as `Authorization: Bearer`. */
  token: string;
  /** Optional fetch override (tests / non-browser runtimes). Defaults to global fetch. */
  fetch?: typeof fetch;
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

/**
 * NvaultClient is the transport layer for the zero-knowledge cloud tier. It
 * uploads and downloads **ciphertext only** — it never sees plaintext. Pair it
 * with the crypto helpers (`./crypto`) to seal/open envelopes client-side.
 *
 * The common flow:
 *   const enc = await sealEnvelope(plaintext, recipients, aad)   // ./crypto
 *   await client.push([{ key, kind, ciphertext: JSON.stringify(enc) }])
 *   const { items } = await client.pull()
 *   const plain = await openEnvelope(JSON.parse(items[0].ciphertext), identity)
 */
export class NvaultClient {
  private readonly opts: NvaultClientOptions;
  private readonly doFetch: typeof fetch;

  constructor(opts: NvaultClientOptions) {
    this.opts = opts;
    this.doFetch = opts.fetch ?? globalThis.fetch;
    if (!this.doFetch) {
      throw new NvaultError("no fetch implementation available; pass opts.fetch");
    }
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.opts.token}`,
      "Content-Type": "application/json",
    };
  }

  /** Download every ciphertext item for the configured environment. */
  async pull(): Promise<WireItem[]> {
    const url = `${this.opts.baseUrl.replace(/\/$/, "")}/sync/pull?org=${encodeURIComponent(
      this.opts.org,
    )}&env=${encodeURIComponent(this.opts.env)}`;
    const res = await this.doFetch(url, { method: "GET", headers: this.headers() });
    if (!res.ok) {
      throw new NvaultError(`pull failed: ${await res.text()}`, res.status);
    }
    const body = (await res.json()) as PullResponse;
    return body.items ?? [];
  }

  /** Upload ciphertext items. Each item's `ciphertext` must be a serialized envelope. */
  async push(items: WireItem[]): Promise<PushResponse> {
    const reqBody: PushRequest = { org: this.opts.org, env: this.opts.env, items };
    const url = `${this.opts.baseUrl.replace(/\/$/, "")}/sync/push`;
    const res = await this.doFetch(url, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(reqBody),
    });
    if (!res.ok) {
      throw new NvaultError(`push failed: ${await res.text()}`, res.status);
    }
    return (await res.json()) as PushResponse;
  }
}

export type { Kind, WireItem };
