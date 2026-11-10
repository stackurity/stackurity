import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router";
import { api, type Billing, type BillingDetails, type BillingPlan, type BillingStatus, type Invoice, type List } from "../../api";
import { useAuth } from "../../auth";
import { useAction, useLoad } from "../../hooks";
import { absTime } from "../../format";
import { Table, type Column } from "../../components/Table";
import { Card, CardFooter, EmptyState, ErrorBox, FieldGroup, KeyValues, Loading, Notice, PageHeader } from "../../components/ui";
import { UsageMeter } from "./Usage";
import { confirmAction } from "../../components/ConfirmDialog";
import { errorView } from "../../errors";
import { detailsComplete, detailsRule } from "../../billingDetails";

/** Money in a currency's smallest unit (paise, cents), formatted for people. */
export function money(amount: number, currency: string): string {
  try {
    return new Intl.NumberFormat(undefined, { style: "currency", currency }).format(amount / 100);
  } catch {
    return `${(amount / 100).toFixed(2)} ${currency}`;
  }
}

function day(iso: string | null | undefined): string {
  if (!iso) return "";
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" });
}

const STATUS_WORDS: Record<BillingStatus, string> = {
  trial: "Free trial",
  trial_ended: "Trial ended",
  awaiting_payment: "Waiting for payment",
  active: "Active",
  past_due: "Payment failed, retrying",
  halted: "Payment failed",
  cancelling: "Ends at the end of the period",
  cancelled: "Ended",
  free: "Free plan",
};

const PERIOD_WORDS = { monthly: "month", yearly: "year" } as const;

/** ISO 3166-1 alpha-2 codes, named in the reader's language. */
const COUNTRY_CODES =
  "AD AE AF AG AI AL AM AO AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GT GU GW GY HK HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split(
    " ",
  );

function countryName(code: string): string {
  try {
    return new Intl.DisplayNames(undefined, { type: "region" }).of(code) ?? code;
  } catch {
    return code;
  }
}

/** The plan's price for a period with extra assets, before tax. */
function planTotal(p: BillingPlan, extra: number): number {
  return p.price + (p.extra_asset_price ?? 0) * extra;
}

/** "₹2,999 + 18% GST" or "$35". */
function priceWords(amount: number, p: BillingPlan): string {
  return money(amount, p.currency) + (p.tax_percent > 0 ? ` + ${p.tax_percent}% ${p.tax_label}` : "");
}

const EMPTY_DETAILS: BillingDetails = { legal_name: "", address: "", state: "", tax_id: "" };

/** The fields of who the tax invoices are made out to, for a billing country. */
function DetailsFields({ country, b, d, onChange, idp }: { country: string; b: Billing; d: BillingDetails; onChange: (d: BillingDetails) => void; idp: string }) {
  const rule = detailsRule(country, b);
  const set = (k: keyof BillingDetails) => (e: { target: { value: string } }) => onChange({ ...d, [k]: e.target.value });
  const states = Object.entries(b.indian_states).sort((x, y) => x[1].localeCompare(y[1]));
  return (
    <FieldGroup
      title="Invoice to"
      description={
        rule === "vat"
          ? "Plans in the EU are for businesses: your invoices are made out to your company, with its VAT number, and VAT is reverse charged (you account for it)."
          : rule === "state"
            ? "Your tax invoices are made out to this name and address. The state decides the GST on them (CGST and SGST in Karnataka, IGST elsewhere)."
            : "Your tax invoices are made out to this name and address. Leave them empty to use the organisation's name."
      }
    >
      <div className="field">
        <label htmlFor={`${idp}-name`}>{rule === "vat" ? "Company's legal name" : "Legal name (optional)"}</label>
        <input id={`${idp}-name`} value={d.legal_name} maxLength={200} required={rule === "vat"} onChange={set("legal_name")} autoComplete="organization" />
      </div>
      <div className="field">
        <label htmlFor={`${idp}-address`}>{rule === "vat" ? "Address" : "Address (optional)"}</label>
        <textarea id={`${idp}-address`} rows={3} value={d.address} maxLength={500} required={rule === "vat"} onChange={set("address")} autoComplete="street-address" />
      </div>
      {rule === "state" && (
        <div className="field">
          <label htmlFor={`${idp}-state`}>State</label>
          <select id={`${idp}-state`} value={d.state} onChange={set("state")} aria-describedby={`${idp}-state-hint`}>
            <option value="">Choose…</option>
            {states.map(([code, name]) => (
              <option key={code} value={code}>
                {name}
              </option>
            ))}
          </select>
          <p className="hint" id={`${idp}-state-hint`}>
            The state of the billing address. With a GSTIN it is taken from the GSTIN.
          </p>
        </div>
      )}
      <div className="field">
        <label htmlFor={`${idp}-tax`}>{rule === "vat" ? "VAT number" : rule === "state" ? "GSTIN (optional)" : "Tax number (optional)"}</label>
        <input
          id={`${idp}-tax`}
          value={d.tax_id}
          maxLength={40}
          required={rule === "vat"}
          onChange={set("tax_id")}
          aria-describedby={`${idp}-tax-hint`}
          placeholder={rule === "vat" ? `${country === "GR" ? "EL" : country}123456789` : rule === "state" ? "29ABCDE1234F1Z5" : ""}
        />
        <p className="hint" id={`${idp}-tax-hint`}>
          {rule === "vat"
            ? "With or without the country prefix. It must be a valid VAT number for the billing country."
            : rule === "state"
              ? "For a GST-registered business: printed on your invoices."
              : "Printed on your invoices if you give one."}
        </p>
      </div>
    </FieldGroup>
  );
}

/** Settings, Plan and billing (admins, hosted edition). */
export function BillingPage() {
  const { meta } = useAuth();
  const res = useLoad(() => (meta?.billing ? api.get<Billing>("/billing") : Promise.resolve(null)), [meta?.billing]);
  const [billing, setBilling] = useState<Billing | null>(null);
  useEffect(() => {
    if (res.data) setBilling(res.data);
  }, [res.data]);
  const b = billing;
  return (
    <>
      <PageHeader
        title="Plan and billing"
        sub="Plans are bundles of projects and monitored assets, paid monthly or yearly. A bigger plan takes effect now; a smaller one at the end of the period."
        actions={
          <Link className="btn" to="/settings/usage">
            Usage
          </Link>
        }
      />
      {!meta?.billing ? (
        // A self-hosted server has no billing: say where its limits come from.
        <Notice kind="info">
          <strong>Plans and billing are part of Stackurity Cloud.</strong> On your own server, what a workspace includes comes from the
          server's licence and the plan its administrator sets. <Link to="/settings/usage">Usage</Link> shows what it uses.
        </Notice>
      ) : res.error?.status === 404 ? (
        // The server answers 404 for an organisation the operator set up
        // (not billed through Stackurity Cloud): explain, don't show an error.
        <Notice kind="info">
          <strong>This organisation is not billed through Stackurity Cloud.</strong> It was set up by the operator, who
          sets its limits. <Link to="/settings/usage">Usage</Link> shows what it uses.
        </Notice>
      ) : (
        <ErrorBox error={res.error} title="Could not load billing" />
      )}
      {meta?.billing && !b && !res.error && <Loading />}
      {b && (
        <>
          {b.test_mode && (
            <Notice kind="info">
              <strong>Test mode: no real payments.</strong> Payments made here are test payments and no money changes hands.
            </Notice>
          )}
          <Current b={b} onChanged={setBilling} />
          {b.billing_enabled ? (
            <>
              <ChoosePlan b={b} onChanged={setBilling} />
              {b.billing_country && <DetailsCard b={b} onChanged={setBilling} />}
              <Invoices />
            </>
          ) : (
            <PlansSoon b={b} />
          )}
        </>
      )}
    </>
  );
}

function Current({ b: cur, onChanged }: { b: Billing; onChanged: (b: Billing) => void }) {
  const cancel = useAction();
  const doCancel = async () => {
    const until = day(cur.current_period_end);
    const ok = await confirmAction({
      title: "Cancel the subscription?",
      message: `Your plan stays until ${until || "the end of the period"}. Then the organisation becomes read-only: you can still sign in and look, but nothing new is collected and no notifications are sent.`,
      consequence: "Its data is deleted 30 days later unless you subscribe again.",
      action: "Cancel subscription",
      destructive: true,
    });
    if (!ok) return;
    const r = await cancel.run(() => api.post<Billing>("/billing/cancel", {}));
    if (r) onChanged(r);
  };
  const entries: [string, ReactNode][] = [["Status", STATUS_WORDS[cur.status] ?? cur.status]];
  if (cur.plan) {
    entries.push(["Plan", `${cur.plan.name}, ${priceWords(planTotal(cur.plan, cur.extra_assets ?? 0), cur.plan)} per ${PERIOD_WORDS[cur.plan.period]}`]);
    if (cur.extra_assets) entries.push(["Extra assets", cur.extra_assets]);
  } else if (cur.status === "trial" && cur.trial_ends_at) {
    entries.push(["Trial ends", day(cur.trial_ends_at)]);
  }
  if (cur.next_charge) entries.push(["Next charge", `${money(cur.next_charge.amount, cur.next_charge.currency)} on ${day(cur.next_charge.at)}`]);
  if (cur.current_period_end) entries.push(["Current period ends", day(cur.current_period_end)]);
  if (cur.scheduled_change)
    entries.push([
      "Scheduled change",
      `${cur.scheduled_change.plan?.name ?? "Plan"}${cur.scheduled_change.extra_assets ? ` with ${cur.scheduled_change.extra_assets} extra assets` : ""}${
        cur.scheduled_change.at ? ` from ${day(cur.scheduled_change.at)}` : ""
      }`,
    ]);
  if (cur.billing_country) entries.push(["Billing country", `${countryName(cur.billing_country)} (${cur.currency ?? ""})`]);
  if (cur.billing_details?.tax_id) entries.push([cur.billing_country === "IN" ? "GSTIN" : cur.billing_country && cur.vat_countries.includes(cur.billing_country) ? "VAT number" : "Tax number", cur.billing_details.tax_id]);
  entries.push(["Data stored in", cur.region_label]);
  return (
    <Card
      title="Your plan"
      description="What this organisation pays for now, how much of it is used, and when it renews."
      actions={
        cur.status === "active" ? (
          <button type="button" className="btn btn-sm btn-link-danger" onClick={() => void doCancel()} disabled={cancel.pending}>
            Cancel plan
          </button>
        ) : undefined
      }
    >
      <ErrorBox error={cancel.error} title="Could not cancel" />
      {cur.read_only_since && (
        <Notice kind="warn">
          <strong>This organisation is read-only</strong> since {day(cur.read_only_since)}: nothing new is collected and no notifications are sent.
          {cur.deletion_at && <> Its data will be deleted on {day(cur.deletion_at)} unless you choose a plan before then.</>}
        </Notice>
      )}
      {cur.grace_until && (
        <Notice kind="warn">
          Payment failed. Update your payment method by {day(cur.grace_until)}, or the organisation becomes read-only. Nothing is deleted before
          then.
        </Notice>
      )}
      {cur.notice && !cur.grace_until && <p>{cur.notice}</p>}
      {cur.payment_url && (cur.status === "awaiting_payment" || cur.status === "past_due" || cur.status === "halted") && (
        <p>
          <a className="btn btn-primary" href={cur.payment_url}>
            Complete payment
          </a>
        </p>
      )}
      <UsageMeter used={cur.monitored} limit={cur.asset_limit} />
      <UsageMeter used={cur.projects} limit={cur.project_limit} noun="projects" />
      <KeyValues entries={entries} />
    </Card>
  );
}

function ChoosePlan({ b, onChanged }: { b: Billing; onChanged: (b: Billing) => void }) {
  const [country, setCountry] = useState(b.billing_country ?? "");
  const currency = b.currency ?? (country ? (b.country_currency[country] ?? b.default_currency) : "");
  const [period, setPeriod] = useState<"monthly" | "yearly">(b.plan?.period ?? "monthly");
  const plans = b.plans.filter((p) => p.currency === currency && p.period === period);
  const [planId, setPlanId] = useState(b.plan?.id ?? "");
  const plan: BillingPlan | undefined = plans.find((p) => p.id === planId);
  const [extra, setExtra] = useState(String(b.extra_assets ?? 0));
  const [paymentUrl, setPaymentUrl] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [details, setDetails] = useState<BillingDetails>(EMPTY_DETAILS);
  const act = useAction();
  const first = !b.billing_country;

  if (b.plans.length === 0) return null;
  const n = plan?.extra_asset_price ? Number(extra) : 0;
  const valid = plan !== undefined && Number.isInteger(n) && n >= 0 && n <= (plan.max_extra_assets ?? 0);
  const subscribed = b.plan !== null && (b.status === "active" || b.status === "past_due" || b.status === "halted");
  const unchanged = subscribed && b.plan?.id === planId && (b.extra_assets ?? 0) === n;

  const send = async (replace: boolean) => {
    if (!valid || !plan) return;
    setDone(null);
    setPaymentUrl(null);
    const r = await act.run(() =>
      api.post<{ billing: Billing; payment_url: string | null; message?: string }>("/billing/subscribe", {
        plan_id: plan.id,
        extra_assets: n,
        country,
        ...(first ? { billing_details: details } : {}),
        ...(replace ? { replace: true } : {}),
      }),
    );
    if (!r) return;
    onChanged(r.billing);
    if (r.payment_url) {
      setPaymentUrl(r.payment_url);
      if (r.message) setDone(r.message);
    } else if (r.message) setDone(r.message);
    else if (r.billing.scheduled_change) setDone(`Saved. ${plan.name} from the next period.`);
    else setDone(`Saved. You are on ${plan.name} now.`);
  };
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    await send(false);
  };
  /** The payment provider cannot change the subscription's plan (UPI, e-mandate, an Indian card): it is replaced by the bigger plan. */
  const replace = async () => {
    const ok = await confirmAction({
      title: "Replace the subscription with the bigger plan?",
      message:
        "On the payment page you authorise the new plan with your card or UPI and pay the difference for the rest of this period; the new plan then starts at once and is billed in full from the end of the period.",
      consequence: "Your current subscription is cancelled now and nothing more is charged on it; its plan continues until you pay.",
      action: "Replace subscription",
    });
    if (ok) await send(true);
  };
  const replaceRequired = act.error?.code === "replace_required";

  return (
    <Card
      title={subscribed ? "Change your plan" : "Choose a plan"}
      description="Choose how often you are billed, then the plan that fits how many projects and assets you need."
    >
      <form className="form" onSubmit={submit}>
        {replaceRequired ? (
          <Notice kind="warn">
            <p>{act.error && errorView(act.error).text}</p>
            <button type="button" className="btn btn-primary" onClick={() => void replace()} disabled={act.pending}>
              Cancel and subscribe again
            </button>
          </Notice>
        ) : (
          <ErrorBox error={act.error} title="Could not change the plan" />
        )}
        {done && !paymentUrl && <Notice kind="success">{done}</Notice>}
        {paymentUrl ? (
          <Notice kind="info">
            <p>{done ?? "Almost done. Confirm the payment method on the payment page to start the plan."}</p>
            <button type="button" className="btn btn-primary" onClick={() => window.location.assign(paymentUrl)}>
              Continue to the payment page
            </button>
          </Notice>
        ) : (
          <>
            {!b.billing_country && (
              <div className="field">
                <label htmlFor="bill-country">Billing country</label>
                <select id="bill-country" required value={country} onChange={(e) => setCountry(e.target.value)} aria-describedby="bill-country-hint">
                  <option value="">Choose…</option>
                  {COUNTRY_CODES.map((c) => ({ c, name: countryName(c) }))
                    .sort((x, y) => x.name.localeCompare(y.name))
                    .map(({ c, name }) => (
                      <option key={c} value={c}>
                        {name}
                      </option>
                    ))}
                </select>
                <p className="hint" id="bill-country-hint">
                  Customers in India must choose India. Asked once: it sets the currency you pay in{currency ? ` (${currency})` : ""} and the tax
                  on your invoices.
                </p>
              </div>
            )}
            {first && country && <DetailsFields country={country} b={b} d={details} onChange={setDetails} idp="bill-first" />}
            {currency && (
              <>
                <fieldset className="plan-choices">
                  <legend>Billed</legend>
                  {(["monthly", "yearly"] as const).map((p) => (
                    <label key={p} className={`plan-choice${p === period ? " selected" : ""}`}>
                      <input type="radio" name="period" value={p} checked={p === period} onChange={() => setPeriod(p)} />
                      <span>{p === "monthly" ? "Monthly" : "Yearly (two months free)"}</span>
                    </label>
                  ))}
                </fieldset>
                {plans.length === 0 ? (
                  <p className="muted">No plans are offered in {currency} for this period.</p>
                ) : (
                  <fieldset className="plan-choices">
                    <legend>Plan</legend>
                    {plans.map((p) => (
                      <label key={p.id} className={`plan-choice${p.id === planId ? " selected" : ""}`}>
                        <input
                          type="radio"
                          name="plan"
                          value={p.id}
                          checked={p.id === planId}
                          onChange={() => {
                            setPlanId(p.id);
                            if (!p.extra_asset_price) setExtra("0");
                          }}
                        />
                        <span>
                          <strong>{p.name}</strong>: {priceWords(p.price, p)} per {PERIOD_WORDS[p.period]}
                          <span className="small block">
                            {p.max_projects} {p.max_projects === 1 ? "project" : "projects"}, {p.included_assets} monitored assets
                            {p.extra_asset_price ? `, then ${money(p.extra_asset_price, p.currency)} per extra asset per ${PERIOD_WORDS[p.period]}` : ""}
                          </span>
                          {p.description && <span className="small muted block">{p.description}</span>}
                        </span>
                      </label>
                    ))}
                  </fieldset>
                )}
                {plan?.extra_asset_price ? (
                  <div className="field">
                    <label htmlFor="bill-extra">Extra assets</label>
                    <input
                      id="bill-extra"
                      type="number"
                      inputMode="numeric"
                      min={0}
                      max={plan.max_extra_assets}
                      step={1}
                      value={extra}
                      onChange={(e) => setExtra(e.target.value)}
                      aria-invalid={!valid}
                      aria-describedby="bill-extra-hint"
                    />
                    <p className="hint" id="bill-extra-hint">
                      0 to {plan.max_extra_assets}, beyond the {plan.included_assets} included. You monitor {b.monitored} now. At the limit new
                      assets are refused; existing ones keep being checked.
                    </p>
                  </div>
                ) : null}
                <CardFooter
                  status={
                    plan && valid ? (
                      <p className="bill-total">
                        Total: {priceWords(planTotal(plan, n), plan)} per {PERIOD_WORDS[plan.period]}
                        {b.test_mode ? " (test mode)" : ""}
                      </p>
                    ) : (
                      "Pick a plan to see the total."
                    )
                  }
                >
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={act.pending || !valid || unchanged || !country || (first && !detailsComplete(country, details, b))}
                  >
                    {act.pending ? "Saving…" : subscribed ? "Change plan" : "Subscribe"}
                  </button>
                </CardFooter>
              </>
            )}
            {b.contact_url && (
              <p className="small muted">
                Enterprise (more projects and assets, agreements): <a href={b.contact_url}>contact us</a>.
              </p>
            )}
          </>
        )}
      </form>
    </Card>
  );
}

/** Who the tax invoices are made out to, after the first subscription (the country stays). */
function DetailsCard({ b, onChanged }: { b: Billing; onChanged: (b: Billing) => void }) {
  const country = b.billing_country ?? "";
  const saved = b.billing_details ?? EMPTY_DETAILS;
  const [d, setD] = useState<BillingDetails>(saved);
  const [editing, setEditing] = useState(false);
  const act = useAction();
  const save = async (e: FormEvent) => {
    e.preventDefault();
    const r = await act.run(() => api.put<Billing>("/billing/details", d));
    if (r) {
      onChanged(r);
      setEditing(false);
    }
  };
  const lines: [string, ReactNode][] = [
    ["Name", saved.legal_name || <span className="muted">the organisation's name</span>],
    ["Address", saved.address ? <span style={{ whiteSpace: "pre-line" }}>{saved.address}</span> : <span className="muted">not given</span>],
  ];
  if (country === "IN") lines.push(["State", b.indian_states[saved.state] ?? <span className="muted">not given</span>]);
  lines.push([detailsRule(country, b) === "vat" ? "VAT number" : country === "IN" ? "GSTIN" : "Tax number", saved.tax_id || "Not applicable"]);
  return (
    <Card
      title="Billing details"
      description="Who your tax invoices are made out to. Changes apply to the next invoice; invoices already issued stay as they are."
      actions={
        !editing ? (
          <button type="button" className="btn btn-sm" onClick={() => (setD(saved), setEditing(true))}>
            Edit
          </button>
        ) : undefined
      }
    >
      {b.details_needed === "state" && (
        <Notice kind="warn">
          <strong>Add the state of your billing address</strong> to get your tax invoices: it decides the GST on them. Invoices waiting for it are issued
          within minutes of saving.
        </Notice>
      )}
      {b.details_needed === "vat" && (
        <Notice kind="warn">
          <strong>Add your company's legal name, address and VAT number</strong> to get your tax invoices.
        </Notice>
      )}
      {editing ? (
        <form className="form" onSubmit={save}>
          <ErrorBox error={act.error} title="Could not save the billing details" />
          <DetailsFields country={country} b={b} d={d} onChange={setD} idp="bill-details" />
          <CardFooter status={`Billing country: ${countryName(country)}. To change it, contact support.`}>
            <button type="button" className="btn" onClick={() => setEditing(false)} disabled={act.pending}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={act.pending || !detailsComplete(country, d, b)}>
              {act.pending ? "Saving…" : "Save"}
            </button>
          </CardFooter>
        </form>
      ) : (
        <KeyValues entries={lines} />
      )}
    </Card>
  );
}

/** While paid plans cannot be bought yet: the plans and prices, and a contact link. */
function PlansSoon({ b }: { b: Billing }) {
  const tiers = new Map<string, BillingPlan[]>();
  for (const p of b.plans) tiers.set(p.tier, [...(tiers.get(p.tier) ?? []), p]);
  const price = (p: BillingPlan) => `${priceWords(p.price, p)} per ${PERIOD_WORDS[p.period]}`;
  return (
    <Card title="Plans">
      <Notice kind="info">
        Paid plans open soon. To keep using Stackurity after your trial, or for a plan now,{" "}
        <a href={b.contact_url}>contact us</a>.
      </Notice>
      {tiers.size > 0 && (
        <ul className="plan-list">
          {[...tiers.values()].map((ps) => (
            <li key={ps[0].tier}>
              <strong>{ps[0].name}</strong>: {ps[0].max_projects} {ps[0].max_projects === 1 ? "project" : "projects"}, {ps[0].included_assets} monitored
              assets
              {ps[0].extra_asset_price ? `, then ${money(ps[0].extra_asset_price, ps[0].currency)} per extra asset` : ""}.
              <span className="small muted block">{ps.map(price).join(" · ")}</span>
            </li>
          ))}
        </ul>
      )}
      <p>
        <a className="btn btn-primary" href={b.contact_url}>
          Contact us
        </a>
      </p>
    </Card>
  );
}

const invoiceColumns: Column<Invoice>[] = [
  { key: "number", header: "Invoice", cell: (i) => <span className="break">{i.number || i.id}</span> },
  {
    key: "period",
    header: "Period",
    cell: (i) => (i.period_start && i.period_end ? `${day(i.period_start)} to ${day(i.period_end)}` : day(i.issued_at) || "-"),
  },
  { key: "amount", header: "Amount", cell: (i) => money(i.amount, i.currency), numeric: true },
  { key: "status", header: "Status", cell: (i) => i.status },
  { key: "paid", header: "Paid", cell: (i) => (i.paid_at ? <time title={absTime(i.paid_at)}>{day(i.paid_at)}</time> : <span className="muted">not yet</span>) },
  {
    key: "tax",
    header: "Tax invoice",
    cell: (i) =>
      i.tax_invoice ? (
        <a href={i.tax_invoice.url} download={`${i.tax_invoice.number.replaceAll("/", "-")}.pdf`} title={`Download tax invoice ${i.tax_invoice.number} (PDF)`}>
          {i.tax_invoice.number}
        </a>
      ) : (
        <span className="muted">-</span>
      ),
  },
  {
    key: "link",
    header: <span className="sr-only">Open</span>,
    cell: (i) =>
      i.url ? (
        <a href={i.url} target="_blank" rel="noopener noreferrer">
          Open
        </a>
      ) : null,
  },
];

function Invoices() {
  const res = useLoad(() => api.get<List<Invoice>>("/billing/invoices"), []);
  return (
    <Card title="Invoices" description="Every charge, with the payment provider's invoice and, once paid, your tax invoice to download as a PDF.">
      <ErrorBox error={res.error} title="Could not load invoices" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <EmptyState title="No invoices yet">Invoices appear here after the first payment.</EmptyState>}
      {res.data && res.data.items.length > 0 && <Table caption="Invoices" columns={invoiceColumns} rows={res.data.items} rowKey={(i) => i.id} />}
    </Card>
  );
}
