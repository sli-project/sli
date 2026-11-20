CREATE DATABASE IF NOT EXISTS sli_warm;
CREATE TABLE IF NOT EXISTS sli_warm.session_lifecycle_revisions
(
    session_uid FixedString(16), revision UInt32,
    state Enum8('closed'=1,'open'=2,'orphan_logoff'=3),
    server_id UInt16, domain_id UInt16, channel_id UInt16,
    logon_time_utc Nullable(DateTime64(6,'UTC')), logoff_time_utc Nullable(DateTime64(6,'UTC')),
    duration_s Nullable(UInt32), logon_id String,
    logon_source_id Nullable(UInt64), logoff_source_id Nullable(UInt64),
    previous_revision_sha256 Nullable(FixedString(64)), revision_sha256 FixedString(64),
    batch_identity FixedString(64), published_at_utc DateTime64(6,'UTC')
) ENGINE=MergeTree ORDER BY (session_uid,revision,revision_sha256);
ALTER TABLE sli_warm.session_lifecycle_revisions ADD COLUMN IF NOT EXISTS payload_json String DEFAULT '';
CREATE TABLE IF NOT EXISTS sli_warm.event_session_placement_revisions
(
    event_id UInt64, revision UInt32, session_uid FixedString(16), placement LowCardinality(String),
    lifecycle_revision_sha256 FixedString(64), batch_identity FixedString(64), published_at_utc DateTime64(6,'UTC')
) ENGINE=MergeTree ORDER BY (event_id,revision,lifecycle_revision_sha256);
CREATE TABLE IF NOT EXISTS sli_warm.primary_session_batches
(
    batch_identity FixedString(64), revision_count UInt32, placement_count UInt32,
    content_sha256 FixedString(64), published_at_utc DateTime64(6,'UTC')
) ENGINE=MergeTree ORDER BY batch_identity;
CREATE VIEW IF NOT EXISTS sli_warm.primary_sessions_effective_v1 AS
SELECT * FROM (
    SELECT *,max(revision) OVER (PARTITION BY session_uid) AS latest_revision,
        count() OVER (PARTITION BY session_uid,revision) AS revision_rows
    FROM sli_warm.session_lifecycle_revisions
    WHERE payload_json!='' AND batch_identity IN
        (SELECT batch_identity FROM sli_warm.primary_session_batches GROUP BY batch_identity HAVING count()=1)
) WHERE revision=latest_revision AND revision_rows=1;
