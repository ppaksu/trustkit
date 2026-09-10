// RFC 8785 JSON Canonicalization Scheme.
// 명세 docs/DESIGN.md 4.4절. 자체 규칙을 정의하지 않는다.
//
// 이 파일이 프로젝트에서 유일한 직렬화 지점이다. 해시 입력을 만드는 코드는
// 전부 여기를 거쳐야 한다. 두 곳에서 각자 구현하면 경계값에서 갈라지고,
// 증상은 해시 불일치 하나로만 나타난다.

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [k: string]: JsonValue };

export class CanonicalizationError extends Error {}

/**
 * RFC 8785 로 직렬화한다.
 *
 * 숫자와 문자열 이스케이프는 `JSON.stringify` 에 위임한다. JCS 가 요구하는
 * 숫자 표현이 ECMAScript 의 Number::toString 이고, 문자열 이스케이프 규칙도
 * 동일하기 때문이다. 이 함수가 추가로 하는 일은 두 가지뿐이다.
 *
 *   1. 객체 키를 UTF-16 코드 유닛 순서로 정렬 (JS 기본 문자열 정렬이 그것이다)
 *   2. JSON 데이터 모델을 벗어나는 값을 거부
 *
 * `JSON.stringify` 는 NaN 과 Infinity 를 조용히 null 로 바꾸므로 직접 막는다.
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
      // -0 은 JCS 에서 0 과 같은 표현이어야 한다. JSON.stringify(-0) 는 "0" 이다.
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
  const keys = Object.keys(obj).sort(); // UTF-16 코드 유닛 순서
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

/** 직렬화 결과의 UTF-8 바이트. 해시 입력은 항상 이 함수를 거친다. */
export function canonicalBytes(value: JsonValue): Buffer {
  return Buffer.from(canonicalize(value), "utf8");
}
