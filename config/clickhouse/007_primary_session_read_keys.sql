ALTER TABLE sli_warm.session_lifecycle_revisions ADD COLUMN IF NOT EXISTS primary_payload_present UInt8 DEFAULT notEmpty(payload_json);
ALTER TABLE sli_warm.session_lifecycle_revisions ADD COLUMN IF NOT EXISTS primary_logon_sid String DEFAULT lowerUTF8(JSONExtractString(payload_json,'logon','target_user_sid'));
ALTER TABLE sli_warm.session_lifecycle_revisions MATERIALIZE COLUMN primary_payload_present, MATERIALIZE COLUMN primary_logon_sid SETTINGS mutations_sync=2;
ALTER TABLE sli_warm.session_lifecycle_revisions MODIFY COLUMN primary_logon_sid String MATERIALIZED lowerUTF8(JSONExtractString(payload_json,'logon','target_user_sid'));
ALTER TABLE sli_warm.session_lifecycle_revisions MODIFY COLUMN primary_payload_present UInt8 MATERIALIZED notEmpty(payload_json);
