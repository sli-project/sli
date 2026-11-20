CREATE TABLE IF NOT EXISTS sli_warm.session_lifecycle_revisions
(
    session_uid FixedString(16),
    revision UInt32,
    state Enum8('closed'=1,'open'=2,'orphan_logoff'=3),
    server_id UInt16,
    domain_id UInt16,
    channel_id UInt16,
    logon_time_utc Nullable(DateTime64(6,'UTC')),
    logoff_time_utc Nullable(DateTime64(6,'UTC')),
    duration_s Nullable(UInt32),
    logon_id String,
    logon_source_id Nullable(UInt64),
    logoff_source_id Nullable(UInt64),
    previous_revision_sha256 Nullable(FixedString(64)),
    revision_sha256 FixedString(64),
    batch_identity FixedString(64),
    published_at_utc DateTime64(6,'UTC')
)
ENGINE=MergeTree
ORDER BY (session_uid,revision,revision_sha256);

CREATE TABLE IF NOT EXISTS sli_warm.event_session_placement_revisions
(
    event_id UInt64,
    revision UInt32,
    session_uid FixedString(16),
    placement LowCardinality(String),
    lifecycle_revision_sha256 FixedString(64),
    batch_identity FixedString(64),
    published_at_utc DateTime64(6,'UTC')
)
ENGINE=MergeTree
ORDER BY (event_id,revision,lifecycle_revision_sha256);

CREATE TABLE IF NOT EXISTS sli_warm.authentication_session_derived_outputs
(
    output_identity FixedString(64),
    batch_identity FixedString(64),
    candidate_identity_sha256 FixedString(64),
    policy_fingerprint FixedString(64),
    derived_output_digest FixedString(64),
    source_reference_digest FixedString(64),
    manifest_digest FixedString(64),
    continuity_declaration_scope_identity String,
    continuity_declaration_sha256 FixedString(64),
    source_count UInt32,
    observation_count UInt32,
    payload_json String,
    published_at_utc DateTime64(6,'UTC')
)
ENGINE=MergeTree
ORDER BY output_identity;

CREATE VIEW IF NOT EXISTS sli_warm.sessions_effective_v1 AS
WITH combined AS
(
    SELECT
        session_uid,toUInt32(0) AS revision,state,
        toUInt16(server_id) AS server_id,toUInt16(domain_id) AS domain_id,
        toUInt16(channel_id) AS channel_id,
        toNullable(logon_time_utc) AS logon_time_utc,logoff_time_utc,duration_s,
        logon_id,logon_source_id,logoff_source_id,
        CAST(NULL,'Nullable(FixedString(64))') AS previous_revision_sha256,
        toFixedString(repeat('0',64),64) AS revision_sha256
    FROM sli_warm.sessions
    UNION ALL
    SELECT
        session_uid,revision,state,server_id,domain_id,channel_id,
        logon_time_utc,logoff_time_utc,duration_s,logon_id,
        logon_source_id,logoff_source_id,previous_revision_sha256,
        revision_sha256
    FROM sli_warm.session_lifecycle_revisions
), ranked AS
(
    SELECT *,
           max(revision) OVER (PARTITION BY session_uid) AS max_revision,
           count() OVER (PARTITION BY session_uid,revision) AS revision_rows
    FROM combined
)
SELECT
    session_uid,revision,state,server_id,domain_id,channel_id,
    logon_time_utc,logoff_time_utc,duration_s,logon_id,
    logon_source_id,logoff_source_id,previous_revision_sha256,revision_sha256
FROM ranked
WHERE revision=max_revision AND revision_rows=1;

CREATE VIEW IF NOT EXISTS sli_warm.event_placement_effective_v1 AS
WITH combined AS
(
    SELECT
        event_id,toUInt32(0) AS revision,session_uid,placement,
        archived_payload_path,archived_payload_line,normalized_hash,
        toFixedString(repeat('0',64),64) AS lifecycle_revision_sha256
    FROM sli_warm.event_placement
    UNION ALL
    SELECT
        revision.event_id,revision.revision,
        CAST(revision.session_uid,'Nullable(FixedString(16))') AS session_uid,
        revision.placement,base.archived_payload_path,
        base.archived_payload_line,base.normalized_hash,
        revision.lifecycle_revision_sha256
    FROM sli_warm.event_session_placement_revisions revision
    INNER JOIN sli_warm.event_placement base
      ON base.event_id=revision.event_id
), ranked AS
(
    SELECT *,
           max(revision) OVER (PARTITION BY event_id) AS max_revision,
           count() OVER (PARTITION BY event_id,revision) AS revision_rows
    FROM combined
)
SELECT
    event_id,revision,session_uid,placement,archived_payload_path,
    archived_payload_line,normalized_hash,lifecycle_revision_sha256
FROM ranked
WHERE revision=max_revision AND revision_rows=1;

CREATE VIEW IF NOT EXISTS sli_warm.session_lifecycle_conflicts_v1 AS
SELECT 'session' AS object_kind,lower(hex(session_uid)) AS object_key,
       revision,count() AS conflicting_rows
FROM sli_warm.session_lifecycle_revisions
GROUP BY session_uid,revision
HAVING conflicting_rows>1
UNION ALL
SELECT 'event' AS object_kind,toString(event_id) AS object_key,
       revision,count() AS conflicting_rows
FROM sli_warm.event_session_placement_revisions
GROUP BY event_id,revision
HAVING conflicting_rows>1;
