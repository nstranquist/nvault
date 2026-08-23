/** Parse one JSON value and reject duplicate fields, trailing data, and deep nesting. */
export function parseUnambiguousJSON(
  input: string,
  label = "JSON",
  maximumDepth = 16,
): unknown {
  let offset = 0;
  const fail = (message: string): never => {
    throw new Error(`${label} is invalid: ${message}`);
  };
  const skipWhitespace = () => {
    while (
      input[offset] === " " ||
      input[offset] === "\n" ||
      input[offset] === "\r" ||
      input[offset] === "\t"
    ) {
      offset++;
    }
  };
  const scanString = (): string => {
    if (input[offset] !== '"') fail("expected a string");
    const start = offset++;
    while (offset < input.length) {
      const code = input.charCodeAt(offset);
      if (code === 0x22) {
        offset++;
        try {
          return JSON.parse(input.slice(start, offset)) as string;
        } catch {
          fail("invalid string escape");
        }
      }
      if (code < 0x20) fail("unescaped control character in string");
      if (code === 0x5c) {
        offset++;
        const escape = input[offset];
        if (escape === "u") {
          const hex = input.slice(offset + 1, offset + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("invalid Unicode escape");
          offset += 5;
          continue;
        }
        if (!escape || !'"\\/bfnrt'.includes(escape))
          fail("invalid string escape");
      }
      offset++;
    }
    return fail("unterminated string");
  };
  const scanNumber = () => {
    const token = input
      .slice(offset)
      .match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/)?.[0];
    if (!token) throw new Error(`${label} is invalid: invalid value`);
    offset += token.length;
  };
  const scanLiteral = (literal: "true" | "false" | "null") => {
    if (!input.startsWith(literal, offset)) fail("invalid value");
    offset += literal.length;
  };
  const scanValue = (depth: number): void => {
    if (depth > maximumDepth) fail(`nesting exceeds ${maximumDepth}`);
    skipWhitespace();
    const character = input[offset];
    if (character === "{") {
      offset++;
      skipWhitespace();
      const fields = new Set<string>();
      if (input[offset] === "}") {
        offset++;
        return;
      }
      while (true) {
        const field = scanString();
        if (fields.has(field)) fail(`duplicate field ${JSON.stringify(field)}`);
        fields.add(field);
        skipWhitespace();
        if (input[offset++] !== ":") fail("expected a colon");
        scanValue(depth + 1);
        skipWhitespace();
        const separator = input[offset++];
        if (separator === "}") return;
        if (separator !== ",") fail("expected a comma or object terminator");
        skipWhitespace();
      }
    }
    if (character === "[") {
      offset++;
      skipWhitespace();
      if (input[offset] === "]") {
        offset++;
        return;
      }
      while (true) {
        scanValue(depth + 1);
        skipWhitespace();
        const separator = input[offset++];
        if (separator === "]") return;
        if (separator !== ",") fail("expected a comma or array terminator");
      }
    }
    if (character === '"') {
      scanString();
      return;
    }
    if (character === "t") return scanLiteral("true");
    if (character === "f") return scanLiteral("false");
    if (character === "n") return scanLiteral("null");
    scanNumber();
  };
  scanValue(0);
  skipWhitespace();
  if (offset !== input.length) fail("trailing data");
  return JSON.parse(input) as unknown;
}
