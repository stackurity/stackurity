-- Relations are also followed backwards: the workloads deployed as an image
-- (for its exposure) and what runs on a host or cluster.
CREATE INDEX asset_relations_to ON asset_relations (to_asset, kind);
