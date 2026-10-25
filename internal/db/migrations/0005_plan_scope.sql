-- A plan is scoped to one policy and one change type, and only a plan that
-- is still awaiting approval can gain actions. Approved plans never grow.
DROP INDEX IF EXISTS remediation_plans_active;
CREATE UNIQUE INDEX remediation_plans_proposed ON remediation_plans
    (component_id, package, target_version, target, COALESCE(policy_id, 0), change_type)
    WHERE status = 'proposed';
