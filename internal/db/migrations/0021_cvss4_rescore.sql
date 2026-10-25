-- CVSS v4 vectors are now scored. Clearing the cursor makes the next sync of
-- each OSV feed download its full archive once, so stored advisories are
-- rated again instead of only those that change upstream.
UPDATE feeds SET cursor = '' WHERE name LIKE 'osv:%';
