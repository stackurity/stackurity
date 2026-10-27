import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router";
import { api, type Billing, type BillingPlan, type BillingStatus, type Invoice, type List } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { absTime } from "../../format";
import { Table, type Column } from "../../components/Table";
import { Card, EmptyState, ErrorBox, KeyValues, Loading, Notice, PageHeader } from "../../components/ui";
import { UsageMeter } from "./Usage";

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
  free: "Free tier",
  awaiting_payment: "Waiting for payment",
  active: "Active",
  past_due: "Payment failed, retrying",
  halted: "Payment failed",
  cancelling: "Ends at the end of the period",
  cancelled: "Cancelled",
};

const PERIOD_WORDS = { monthly: "month", yearly: "year" } as const;

/** Settings, Plan and billing (admins, hosted edition). */
export function BillingPage() {
  const res = useLoad(() => api.get<Billing>("/billing"), []);
  const [billing, setBilling] = useState<Billing | null>(null);
  useEffect(() => {
    if (res.data) setBilling(res.data);
  }, [res.data]);
  const b = billing;
  return (
    <>
      <PageHeader
        title="Plan and billing"
        sub="You pay for the number of assets you choose. Raising it takes effect now; lowering it takes effect at the end of the period."
        actions={
          <Link className="btn" to="/settings/usage">
            Usage
          </Link>
        }
      />
      <ErrorBox error={res.error} title="Could not load billing" />
      {!b && !res.error && <Loading />}
      {b && (
        <>
          {b.test_mode && (
            <Notice kind="info">
              <strong>Test mode: no real payments.</strong> Payments made here are test payments and no money changes hands.
            </Notice>
          )}
          <Current b={b} onChanged={setBilling} />
          <ChoosePlan b={b} onChanged={setBilling} />
          <Invoices />
        </>
      )}
    </>
  );
}

function Current({ b: cur, onChanged }: { b: Billing; onChanged: (b: Billing) => void }) {
  const cancel = useAction();
  const doCancel = async () => {
    const until = day(cur.current_period_end);
    const ok = window.confirm(
      `Your plan stays until ${until || "the end of the period"}, then the organisation moves to the free tier of ${cur.free_assets} assets. ` +
        "Nothing is deleted; assets above the free tier keep being checked but no new ones can be added.",
    );
    if (!ok) return;
    const r = await cancel.run(() => api.post<Billing>("/billing/cancel", {}));
    if (r) onChanged(r);
  };
  const entries: [string, ReactNode][] = [
    ["Status", STATUS_WORDS[cur.status] ?? cur.status],
    ["Plan", cur.plan ? cur.plan.name : `Free tier (${cur.free_assets} assets)`],
  ];
  if (cur.assets_paid !== null) entries.push(["Assets paid for", cur.assets_paid]);
  if (cur.next_charge) entries.push(["Next charge", `${money(cur.next_charge.amount, cur.next_charge.currency)} on ${day(cur.next_charge.at)}`]);
  if (cur.current_period_end) entries.push(["Current period ends", day(cur.current_period_end)]);
  if (cur.scheduled_change)
    entries.push(["Scheduled change", `${cur.scheduled_change.assets} assets from ${day(cur.scheduled_change.at)}`]);
  entries.push(["Data stored in", cur.region_label]);
  return (
    <Card
      title="Your plan"
      actions={
        cur.status === "active" ? (
          <button type="button" className="btn btn-sm btn-link-danger" onClick={() => void doCancel()} disabled={cancel.pending}>
            Cancel plan
          </button>
        ) : undefined
      }
    >
      <ErrorBox error={cancel.error} title="Could not cancel" />
      {cur.grace_until && (
        <Notice kind="warn">
          Payment failed. Update your payment method by {day(cur.grace_until)}, or the limit drops to the free tier. Assets already monitored keep
          being checked either way.
        </Notice>
      )}
      {cur.notice && <p>{cur.notice}</p>}
      {cur.payment_url && (cur.status === "awaiting_payment" || cur.status === "past_due" || cur.status === "halted") && (
        <p>
          <a className="btn btn-primary" href={cur.payment_url}>
            Complete payment
          </a>
        </p>
      )}
      <UsageMeter used={cur.monitored} limit={cur.asset_limit} />
      <KeyValues entries={entries} />
    </Card>
  );
}

function ChoosePlan({ b, onChanged }: { b: Billing; onChanged: (b: Billing) => void }) {
  const plans = b.plans;
  const [planId, setPlanId] = useState(b.plan?.id ?? plans[0]?.id ?? "");
  const plan: BillingPlan | undefined = plans.find((p) => p.id === planId);
  const initial = (p?: BillingPlan) => {
    if (!p) return "";
    if (b.plan?.id === p.id && b.assets_paid !== null) return String(b.assets_paid);
    return String(Math.min(p.max_assets, Math.max(b.monitored, p.min_assets)));
  };
  const [assets, setAssets] = useState(() => initial(plan));
  const [paymentUrl, setPaymentUrl] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const act = useAction();

  if (plans.length === 0) return null;
  const n = Number(assets);
  const valid = plan !== undefined && Number.isInteger(n) && n >= plan.min_assets && n <= plan.max_assets;
  const subscribed = b.plan !== null && (b.status === "active" || b.status === "past_due" || b.status === "halted");
  const unchanged = subscribed && b.plan?.id === planId && b.assets_paid === n;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    setDone(null);
    setPaymentUrl(null);
    const r = await act.run(() => api.post<{ billing: Billing; payment_url: string | null }>("/billing/subscribe", { plan_id: planId, assets: n }));
    if (!r) return;
    onChanged(r.billing);
    if (r.payment_url) setPaymentUrl(r.payment_url);
    else setDone(n < (b.assets_paid ?? 0) ? `Saved. ${n} assets from the next period.` : `Saved. You now pay for ${n} assets.`);
  };

  return (
    <Card title={subscribed ? "Change your plan" : "Choose a plan"}>
      <form className="form" onSubmit={submit}>
        <ErrorBox error={act.error} title="Could not change the plan" />
        {done && <Notice kind="success">{done}</Notice>}
        {paymentUrl ? (
          <Notice kind="info">
            <p>Almost done. Confirm the payment method on the payment page to start the plan.</p>
            <button type="button" className="btn btn-primary" onClick={() => window.location.assign(paymentUrl)}>
              Continue to the payment page
            </button>
          </Notice>
        ) : (
          <>
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
                      setAssets(initial(p));
                    }}
                  />
                  <span>
                    <strong>{p.name}</strong>: {money(p.price_per_asset, p.currency)} per asset per {PERIOD_WORDS[p.period]}
                    {p.description && <span className="small muted block">{p.description}</span>}
                  </span>
                </label>
              ))}
            </fieldset>
            {plan && (
              <div className="field">
                <label htmlFor="bill-assets">Assets to pay for</label>
                <input
                  id="bill-assets"
                  type="number"
                  inputMode="numeric"
                  min={plan.min_assets}
                  max={plan.max_assets}
                  step={1}
                  required
                  value={assets}
                  onChange={(e) => setAssets(e.target.value)}
                  aria-invalid={!valid}
                  aria-describedby="bill-assets-hint"
                />
                <p className="hint" id="bill-assets-hint">
                  Between {plan.min_assets} and {plan.max_assets}. You monitor {b.monitored} now. This is also your limit: at it, new assets are refused
                  and existing ones keep being checked.
                </p>
                {valid && (
                  <p className="bill-total">
                    {money(plan.price_per_asset * n, plan.currency)} per {PERIOD_WORDS[plan.period]}
                    {b.test_mode ? " (test mode)" : ""}
                  </p>
                )}
              </div>
            )}
            <div className="form-actions">
              <button type="submit" className="btn btn-primary" disabled={act.pending || !valid || unchanged}>
                {act.pending ? "Saving…" : subscribed ? "Change plan" : "Subscribe"}
              </button>
            </div>
          </>
        )}
      </form>
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
    <Card title="Invoices">
      <ErrorBox error={res.error} title="Could not load invoices" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <EmptyState title="No invoices yet">Invoices appear here after the first payment.</EmptyState>}
      {res.data && res.data.items.length > 0 && <Table caption="Invoices" columns={invoiceColumns} rows={res.data.items} rowKey={(i) => i.id} />}
    </Card>
  );
}
