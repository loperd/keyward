/** A payment-network mark derived from the IIN, with an explicit vault brand
 * taking precedence when it is present.  Only the first six visible digits of
 * a masked card number are needed; the full PAN never reaches this component. */
export type CardBrand = "visa" | "mastercard" | "amex" | "discover" | "jcb" | "diners" | "unionpay" | "maestro" | "mir" | "rupay" | "other";

const aliases: Record<string, CardBrand> = {
  visa: "visa",
  mastercard: "mastercard",
  "master card": "mastercard",
  "american express": "amex",
  amex: "amex",
  discover: "discover",
  jcb: "jcb",
  "diners club": "diners",
  diners: "diners",
  unionpay: "unionpay",
  maestro: "maestro",
  mir: "mir",
  rupay: "rupay",
  other: "other",
};

export function detectCardBrand(number?: string | null, explicit?: string | null): CardBrand | null {
  const named = explicit?.trim().toLowerCase();
  if (named && aliases[named] && aliases[named] !== "other") return aliases[named];
  const digits = (number ?? "").replace(/\D/g, "");
  if (/^4/.test(digits)) return "visa";
  const first4 = Number(digits.slice(0, 4));
  if (/^5[1-5]/.test(digits) || (first4 >= 2221 && first4 <= 2720)) return "mastercard";
  if (/^3[47]/.test(digits)) return "amex";
  if (/^6(?:011|5|4[4-9])/.test(digits)) return "discover";
  if (/^(?:2131|1800|35)/.test(digits)) return "jcb";
  if (/^3(?:0[0-5]|[68])/.test(digits)) return "diners";
  if (/^62/.test(digits)) return "unionpay";
  if (/^(?:50|5[6-9]|6)/.test(digits)) return "maestro";
  if (/^220[0-4]/.test(digits)) return "mir";
  if (/^(?:60|65|81|82)/.test(digits)) return "rupay";
  return named ? aliases[named] ?? "other" : null;
}

export function CardBrandMark({ brand, compact = false }: { brand: CardBrand | null; compact?: boolean }) {
  if (!brand || brand === "other") return null;
  if (brand === "mastercard") {
    return <span className={`card-brand mastercard${compact ? " compact" : ""}`} title="Mastercard" aria-label="Mastercard"><i /><i /></span>;
  }
  const label: Record<Exclude<CardBrand, "mastercard" | "other">, string> = {
    visa: "VISA", amex: "AMEX", discover: "DISCOVER", jcb: "JCB", diners: "DINERS", unionpay: "UnionPay", maestro: "maestro", mir: "МИР", rupay: "RuPay",
  };
  return <span className={`card-brand ${brand}${compact ? " compact" : ""}`} title={label[brand]} aria-label={label[brand]}>{label[brand]}</span>;
}
