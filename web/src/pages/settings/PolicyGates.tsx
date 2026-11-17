import { useState } from "react";
import { Link } from "react-router";
import { api, type GatePolicyItem, type GatePolicyList, type GatePolicyRequest, type GateViolation, type List } from "../../api";
import { useAuth } from "../../auth";
import { gatePoliciesEmpty } from "../../emptyCopy";
import { useAction, useLoad } from "../../hooks";
import { confirmAction } from "../../components/ConfirmDialog";
import { OrgPoliciesBody, PolicyForm, type OrgPolicyActions } from "../../components/PolicyGates";
import { Card, Code, EmptyState, ErrorBox, GoodToKnow, Loading, Notice, PageHeader } from "../../components/ui";
import { VIOLATIONS_PATH } from "../../policyGates";

/**
 * Settings → Policy gates: the organisation's policies (security reads,
 * admins change them). Projects and assets turn them off or edit their own
 * copy on their pages (components/PolicyGates.tsx).
 */
export function PolicyGatesPage() {
  const { can, has } = useAuth();
  const canManage = can("admin");
  const enforceAvailable = has("gate_enforce");
  const res = useLoad(() => api.getAll<GatePolicyList>("/gate-policies"), []);
  const vs = useLoad(() => api.getAll<List<GateViolation>>("/gate-policies/violations"), []);
  const act = useAction();
  const [note, setNote] = useState("");
  const [adding, setAdding] = useState(false);
  const reload = () => {
    res.reload();
    vs.reload();
  };
  const save = async (req: GatePolicyRequest, id?: number) => {
    const ok = await act.run(() => (id ? api.put(`/gate-policies/${id}`, req) : api.post("/gate-policies", req)).then(() => true));
    if (ok) {
      setNote(id ? `${req.name} saved.` : `${req.name} added in ${req.mode} mode.`);
      reload();
    }
    return Boolean(ok);
  };
  const actions: OrgPolicyActions = {
    save,
    remove: async (p: GatePolicyItem) => {
      const ok = await confirmAction({
        title: `Delete ${p.name}?`,
        consequence: "CI and deploy checks stop applying it everywhere. Copies that projects or assets edited from it stay, as their own policies. Its history stays in the audit log.",
        action: "Delete policy",
        destructive: true,
        typeToConfirm: p.name,
      });
      if (!ok) return;
      if (await act.run(() => api.del(`/gate-policies/${p.id}`).then(() => true))) {
        setNote(`${p.name} deleted.`);
        reload();
      }
    },
  };

  const header = (
    <PageHeader
      title="Policy gates"
      sub="Rules your organisation writes once, such as no known exploited vulnerability on an internet-facing asset. CI jobs, deploy checks, the Dashboard and the weekly summary all read the same answer."
    />
  );
  if (res.error) {
    return (
      <>
        {header}
        <ErrorBox error={res.error} title="Could not load the policy gates" />
      </>
    );
  }
  if (!res.data) {
    return (
      <>
        {header}
        <Loading />
      </>
    );
  }
  const items = res.data.items;
  return (
    <>
      {header}
      {note && <Notice kind="success">{note}</Notice>}
      <ErrorBox error={act.error} title="Could not change the policy" />
      <ErrorBox error={vs.error} title="Could not count the violations" />
      {items.length === 0 && !adding ? (
        <Card title="Organisation policies" description="Rules every asset in the organisation is held to.">
          <EmptyState {...gatePoliciesEmpty(canManage)} action={{ ...gatePoliciesEmpty(canManage).action!, onClick: () => setAdding(true) }} />
        </Card>
      ) : items.length === 0 ? (
        <Card title="Add a policy" description="A new policy starts in warn mode: CI and deploy checks report its violations and pass.">
          <PolicyForm
            policy={null}
            enforceAvailable={enforceAvailable}
            pending={act.pending}
            onCancel={() => setAdding(false)}
            onSave={async (req) => {
              if (await save(req)) setAdding(false);
            }}
          />
        </Card>
      ) : (
        <OrgPoliciesBody items={items} violations={vs.data?.items} canManage={canManage} enforceAvailable={enforceAvailable} pending={act.pending} actions={actions} />
      )}
      <GoodToKnow>
        <ul>
          <li>
            <Code>stackurity scan</Code> in CI checks these policies after each upload. Warn-mode violations are printed and the job passes; an enforced
            violation fails it.
          </li>
          <li>
            Every current violation is listed under <Link to={VIOLATIONS_PATH}>Fixes → Policy violations</Link>, and the weekly summary counts them per
            policy.
          </li>
          <li>Snoozed issues, accepted risks and false positives never count against a policy.</li>
          <li>Every change, including turning a policy off for a project or asset, is recorded in the audit log.</li>
        </ul>
      </GoodToKnow>
    </>
  );
}
