import type { BillingDetails } from "./api";

/** What the billing details need for a country: EU businesses give a VAT number, Indian addresses a state. */
export function detailsRule(country: string, b: { vat_countries: string[] }): "vat" | "state" | "optional" {
  if (country === "IN") return "state";
  if (b.vat_countries.includes(country)) return "vat";
  return "optional";
}

/** Whether the details are complete enough to send for a country (the server checks the formats). */
export function detailsComplete(country: string, d: BillingDetails, b: { vat_countries: string[] }): boolean {
  switch (detailsRule(country, b)) {
    case "vat":
      return d.legal_name.trim() !== "" && d.address.trim() !== "" && d.tax_id.trim() !== "";
    case "state":
      return d.state !== "" || d.tax_id.trim() !== "";
    default:
      return true;
  }
}
