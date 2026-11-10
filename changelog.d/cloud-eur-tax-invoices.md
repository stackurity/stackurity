### Added

- **Stackurity Cloud: euro billing for EU businesses, and our own tax invoices.** Organisations whose billing country is one of the 27 EU member states pay in EUR (Starter €10, Team €35, Business €79 a month; extra assets €1.50), without VAT: they are business customers, give their legal name, address and VAT number at the first subscription (checked for their country's format, and optionally in VIES), and are reverse charged. India still pays INR with GST; everyone else, the United Kingdom, Switzerland and Norway included, USD. Plan and billing asks for the billing details with the country, shows them with an **Edit** button, and lists a **Tax invoice** PDF next to each paid invoice: numbered `STK/26-27/0001` per Indian financial year, with CGST and SGST, IGST, or export under LUT (and the reverse-charge note in the EU). New `GET /api/v1/billing/invoices/{id}/pdf` and `PUT /api/v1/billing/details`; `POST /billing/subscribe` takes `billing_details`. See [API](docs/api.md#get-billinginvoicesidpdf).

### Changed

- The licensed build's modules (`tools/eedeps`) add `github.com/signintech/gopdf` (MIT) for the tax-invoice PDFs and `golang.org/x/text` as a direct requirement (country names).
