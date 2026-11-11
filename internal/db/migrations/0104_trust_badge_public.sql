-- Trust badge, part 2 (docs/trust-badge.md): what the public badge and
-- trust page show about the organisation. Nothing is public unless the
-- badge is on for Stackurity Cloud (STACKURITY_TRUST_BADGE=on) and the
-- organisation turned it on.
--
--   display_name  the name on the trust page (the organisation's name when
--                 the badge was made; the customer may change it)
--   website_url   the customer's site, linked from the trust page when the
--                 "logo and website link" item is on (https only)
--   logo          the customer's logo for the trust page on paid plans:
--                 PNG, JPEG or WebP, at most 256 KiB, its type checked from
--                 its bytes when uploaded

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE trust_badges
    ADD COLUMN display_name text NOT NULL DEFAULT '' CHECK (length(display_name) <= 80),
    ADD COLUMN website_url  text NOT NULL DEFAULT '' CHECK (website_url = '' OR (website_url ~ '^https://' AND length(website_url) <= 300)),
    ADD COLUMN logo         bytea CHECK (logo IS NULL OR octet_length(logo) <= 262144),
    ADD COLUMN logo_type    text NOT NULL DEFAULT '' CHECK (logo_type IN ('', 'image/png', 'image/jpeg', 'image/webp')),
    ADD CHECK ((logo IS NULL) = (logo_type = ''));
