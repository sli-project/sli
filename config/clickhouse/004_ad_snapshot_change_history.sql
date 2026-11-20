CREATE DATABASE IF NOT EXISTS sli_history;
CREATE TABLE IF NOT EXISTS sli_history.ad_snapshot_changes
(
    batch_id FixedString(64),
    record_id FixedString(64),
    domain_id UInt64,
    family LowCardinality(String),
    observed_at DateTime64(6, 'UTC'),
    payload_json String
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(observed_at)
ORDER BY (domain_id, family, observed_at, batch_id, record_id);
