CREATE DATABASE IF NOT EXISTS sli_history;

CREATE TABLE IF NOT EXISTS sli_history.events
(
    event_db_id UInt64,
    time_created_utc DateTime64(6, 'UTC'),
    event_key UInt32,
    server_id UInt64,
    noise_class LowCardinality(String),
    core_json String,
    facts_json String,
    row_sha256 FixedString(64),
    batch_sha256 FixedString(64),
    INDEX event_db_id_idx event_db_id TYPE minmax GRANULARITY 1
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(time_created_utc)
ORDER BY (time_created_utc, event_db_id);

CREATE TABLE IF NOT EXISTS sli_history.links
(
    event_db_id UInt64,
    entity_id UInt64,
    time_created_utc DateTime64(6, 'UTC'),
    link_role LowCardinality(String),
    details_json String,
    row_sha256 FixedString(64),
    batch_sha256 FixedString(64),
    INDEX event_db_id_idx event_db_id TYPE minmax GRANULARITY 1
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(time_created_utc)
ORDER BY (entity_id, time_created_utc, event_db_id, link_role);

CREATE TABLE IF NOT EXISTS sli_history.published_batches
(
    batch_sha256 FixedString(64),
    first_event_db_id UInt64,
    last_event_db_id UInt64,
    event_count UInt32,
    link_count UInt32,
    event_sequence_sha256 FixedString(64),
    link_sequence_sha256 FixedString(64),
    published_at_utc DateTime64(6, 'UTC')
)
ENGINE = MergeTree
ORDER BY first_event_db_id;

ALTER TABLE sli_history.events ADD COLUMN IF NOT EXISTS batch_sha256 FixedString(64) DEFAULT toFixedString(repeat('0', 64), 64);
ALTER TABLE sli_history.links ADD COLUMN IF NOT EXISTS batch_sha256 FixedString(64) DEFAULT toFixedString(repeat('0', 64), 64);
