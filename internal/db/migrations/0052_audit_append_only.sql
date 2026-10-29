-- The audit log is append-only and tamper-evident (docs/security-audit.md,
-- "Audit log").
--
-- 1. Row-level security gives the application role SELECT and INSERT on
--    audit_events and nothing else: the UPDATE and DELETE policies of
--    migration 0032 and the all-commands "sys" policy of 0010 are replaced.
-- 2. A trigger refuses UPDATE, DELETE and TRUNCATE for every role, the
--    table owner included, with two exceptions:
--      - rows of a workspace that no longer exists: the ON DELETE CASCADE
--        from workspaces when a whole workspace is deleted
--        (Store.DeleteWorkspace). This needs nothing from the caller, so
--        a release from before this migration deletes workspaces as it
--        always did;
--      - a transaction that ran SET LOCAL stackurity.audit_maintenance = 'on'
--        as the table owner (an operator's psql session): the
--        application role has no UPDATE or DELETE policy, so the setting
--        does nothing for it.
-- 3. Every new row is linked into a hash chain per workspace (one more
--    chain for platform events, workspace_id NULL) by the insert trigger,
--    whatever inserted it: chain_seq counts 1, 2, 3 … in the chain,
--    prev_hash is the previous row's hash and
--    hash = sha256(prev_hash || stackurity_audit_payload(row)), in hex.
--    The first row of each chain has chain_seq 1 and prev_hash of 64
--    zeros: that is the marker of where the chain starts. Rows written
--    before this migration keep chain_seq, prev_hash and hash NULL and are
--    not rewritten (a production table can hold hundreds of thousands of
--    rows); `stackurity admin verify-audit` counts them as unchained.
--
-- Nothing here rewrites existing rows: the new columns are nullable
-- without a default (no table rewrite) and the one index is built in the
-- migration's transaction (seconds for a few hundred thousand rows).

ALTER TABLE audit_events
    ADD COLUMN chain_seq bigint,
    ADD COLUMN prev_hash text,
    ADD COLUMN hash      text;

CREATE UNIQUE INDEX audit_events_chain ON audit_events (COALESCE(workspace_id, 0), chain_seq) WHERE chain_seq IS NOT NULL;

-- The newest link of each chain, so that `verify-audit` notices the newest
-- events going missing. Only the insert trigger writes it: row-level
-- security is on with a read-only policy for system scope, so the
-- application role cannot change it (the owner, who runs the trigger
-- function, is exempt as the table is not FORCEd). A deleted workspace's
-- head goes with it.
CREATE TABLE audit_chain_heads (
    id           bigserial PRIMARY KEY,
    workspace_id bigint REFERENCES workspaces(id) ON DELETE CASCADE,
    seq          bigint NOT NULL,
    hash         text NOT NULL,
    first_id     bigint NOT NULL,
    last_id      bigint NOT NULL,
    started_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX audit_chain_heads_chain ON audit_chain_heads ((COALESCE(workspace_id, 0)));
ALTER TABLE audit_chain_heads ENABLE ROW LEVEL SECURITY;
CREATE POLICY sys_select ON audit_chain_heads FOR SELECT USING (stackurity_system());

-- The canonical text of an event that its hash covers (version 1): a JSON
-- array of every column but the chain's own prev_hash and hash. jsonb's
-- text form is deterministic, and the time is written in UTC with
-- microseconds, so the TimeZone setting does not change it.
CREATE FUNCTION stackurity_audit_payload(e audit_events) RETURNS text LANGUAGE sql STABLE AS $$
    SELECT jsonb_build_array(1, e.id, to_char(e.at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), e.workspace_id,
        e.actor_type, e.actor_id, e.actor_name, e.action, e.object_type, e.object_id, e.detail, e.remote_addr, e.chain_seq)::text
$$;

-- Links a new event into its chain. SECURITY DEFINER so that it can use
-- audit_chain_heads; the row lock on the chain's head orders concurrent
-- inserts of one workspace (released at commit). Values the inserter gave
-- for the chain columns are overwritten.
CREATE FUNCTION stackurity_audit_chain() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE
    h audit_chain_heads%ROWTYPE;
BEGIN
    INSERT INTO audit_chain_heads (workspace_id, seq, hash, first_id, last_id)
        VALUES (NEW.workspace_id, 0, repeat('0', 64), NEW.id, NEW.id)
        ON CONFLICT ((COALESCE(workspace_id, 0))) DO NOTHING;
    SELECT * INTO h FROM audit_chain_heads WHERE COALESCE(workspace_id, 0) = COALESCE(NEW.workspace_id, 0) FOR UPDATE;
    NEW.chain_seq := h.seq + 1;
    NEW.prev_hash := h.hash;
    NEW.hash := encode(sha256(convert_to(h.hash || stackurity_audit_payload(NEW), 'UTF8')), 'hex');
    UPDATE audit_chain_heads SET seq = NEW.chain_seq, hash = NEW.hash, last_id = NEW.id WHERE id = h.id;
    RETURN NEW;
END $$;

CREATE TRIGGER audit_events_chain BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION stackurity_audit_chain();

-- Refuses changes to recorded events (see the top of this file).
CREATE FUNCTION stackurity_audit_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF current_setting('stackurity.audit_maintenance', true) = 'on' THEN
        IF TG_LEVEL = 'STATEMENT' THEN
            RETURN NULL;
        ELSIF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    -- The cascade of deleting a whole workspace: by then the workspace row
    -- is gone (the foreign key's action runs after it is deleted).
    IF TG_LEVEL = 'ROW' AND TG_OP = 'DELETE' AND OLD.workspace_id IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM workspaces w WHERE w.id = OLD.workspace_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'the audit log is append-only: % on audit_events is not allowed', TG_OP
        USING ERRCODE = 'insufficient_privilege',
              HINT = 'Events are removed only with their workspace; see docs/security-audit.md, "Audit log".';
END $$;

CREATE TRIGGER audit_events_guard BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION stackurity_audit_guard();
CREATE TRIGGER audit_events_guard_truncate BEFORE TRUNCATE ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION stackurity_audit_guard();

-- Row-level security: read and record, nothing else.
DROP POLICY sys ON audit_events;
DROP POLICY ws_update ON audit_events;
DROP POLICY ws_delete ON audit_events;
CREATE POLICY sys_select ON audit_events FOR SELECT USING (stackurity_system());
CREATE POLICY sys_insert ON audit_events FOR INSERT WITH CHECK (stackurity_system());

-- Grants for the application role, for databases where the migrating user
-- differs (as in 0032). The functions are granted so that inserting works;
-- what the role may do with the heads table is up to its row-level
-- security (read in system scope only).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE audit_chain_heads_id_seq TO stackurity_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION stackurity_audit_payload(audit_events), stackurity_audit_chain(), stackurity_audit_guard() TO stackurity_app';
    END IF;
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
