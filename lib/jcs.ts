// RFC 8785 JSON 정규화. 해시 입력은 전부 이 파일을 거친다.
//
// 두 곳에서 각자 직렬화하면 경계값에서 갈리고, 증상은 "해시 불일치" 하나로만
// 나타난다.

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [k: string]: JsonValue };

export class CanonicalizationError extends Error {}

/**
 * 숫자와 이스케이프는 JSON.stringify 에 위임한다. RFC 가 요구하는 표기와 같다.
 * 직접 하는 건 키 정렬과 비JSON 값 거부 둘뿐이다.
 */
export function canonicalize(value: JsonValue): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";

    case "number":
      if (!Number.isFinite(value)) {
        throw new CanonicalizationError(`JSON 숫자가 아님: ${value}`);
      }
      // JSON.stringify(NaN/Infinity) 는 "null" 을 조용히 돌려준다. 위에서 막는다.
      return JSON.stringify(value);

    case "string":
      return JSON.stringify(value);

    case "object":
      break;

    default:
      throw new CanonicalizationError(`직렬화할 수 없는 타입: ${typeof value}`);
  }

  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalize(v)).join(",") + "]";
  }

  const obj = value as { [k: string]: JsonValue };
  const keys = Object.keys(obj).sort(); // JS 기본 정렬이 RFC 가 요구하는 순서다
  const parts: string[] = [];
  for (const k of keys) {
    const v = obj[k];
    if (v === undefined) {
      throw new CanonicalizationError(`undefined 값: ${k}`);
    }
    parts.push(JSON.stringify(k) + ":" + canonicalize(v));
  }
  return "{" + parts.join(",") + "}";
}

/** 해시 입력용 UTF-8 바이트. */
export function canonicalBytes(value: JsonValue): Buffer {
  return Buffer.from(canonicalize(value), "utf8");
}
