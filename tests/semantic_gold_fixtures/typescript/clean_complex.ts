export function clean_parse_tokens(text: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quoted = false;
  let escaped = false;
  for (const char of text) {
    if (escaped) {
      current += char;
      escaped = false;
    } else if (char === "\\") {
      current += char;
      escaped = true;
    } else if (char === '"') {
      current += char;
      quoted = !quoted;
    } else if (/\s/.test(char) && !quoted) {
      if (current) {
        tokens.push(current);
        current = "";
      }
    } else {
      current += char;
    }
  }
  if (current) tokens.push(current);
  return tokens;
}

export function clean_validate_contract(result: { tier: string; smelly: boolean }): string {
  if (!result || typeof result !== "object") {
    throw new Error("result must be an object");
  }
  const tier = result.tier;
  const smelly = result.smelly;
  if (smelly !== (tier !== "clean")) {
    throw new Error("tier and smelly disagree");
  }
  return tier;
}

export function kindaForwardPayload(payload: Payload): Payload {
  const forwarded = payload;
  return forwarded;
}
