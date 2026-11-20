CREATE DATABASE IF NOT EXISTS sli_history;
CREATE TABLE IF NOT EXISTS sli_history.workstation_observations
(
    id FixedString(64),
    agent_key String,
    entity_id UInt64,
    ad_computer_id Nullable(UInt64),
    family LowCardinality(String),
    event_id UInt32,
    observed_at DateTime64(6, 'UTC'),
    payload_sha256 FixedString(64),
    payload_json String
)
ENGINE = ReplacingMergeTree
ORDER BY id
SETTINGS fsync_after_insert = 1, fsync_part_directory = 1;
