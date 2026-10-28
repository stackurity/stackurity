-- Whether a person named the asset (PATCH /assets/{id}). Collectors never
-- change such a name; an application's generated name ("phpmyadmin on
-- DBC") may get its path added when another application on the same host
-- would have the same name. Additive: a defaulted column, no rewrite.

SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE assets ADD COLUMN name_by_person boolean NOT NULL DEFAULT false;
