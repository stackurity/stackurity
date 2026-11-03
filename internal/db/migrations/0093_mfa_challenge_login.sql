-- How the sign-in that a two-factor challenge belongs to began: password
-- (the local password) or social (a hosted edition's "Continue with
-- Google, Microsoft or GitHub"). The session started after the second
-- factor records it as its login_method. Challenges from an older release
-- are password sign-ins.
ALTER TABLE mfa_challenges ADD COLUMN login_method text NOT NULL DEFAULT 'password';
