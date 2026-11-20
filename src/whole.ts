/** Whole-number checks, kept neutral at call sites. */
export const isWholeNumber = (v: unknown): v is number =>
  typeof v === "number" && Number.isFinite(v) && Math.floor(v) === v;

/** Whole number within the JSON-safe range (|v| <= 2^53 - 1). */
export const isSafeWholeNumber = (v: unknown): v is number =>
  isWholeNumber(v) && Math.abs(v) <= 9007199254740991;
