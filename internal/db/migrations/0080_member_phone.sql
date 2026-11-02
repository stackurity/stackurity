-- A member's phone number (Settings → Users), as contact information only:
-- nothing sends to it and it is not used to sign in. It is kept on the
-- membership, not the account, because accounts are shared by workspaces
-- and one workspace's admins must not change what another sees.
--
-- Additive: a column with a default. Existing members get an empty phone
-- and keep exactly the access they had.

SET LOCAL lock_timeout = '10s';

ALTER TABLE workspace_members ADD COLUMN phone text NOT NULL DEFAULT ''
    CHECK (length(phone) <= 32 AND phone ~ '^[0-9+() .-]*$');
