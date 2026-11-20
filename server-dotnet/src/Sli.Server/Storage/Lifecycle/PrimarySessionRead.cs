namespace Sli.Server.Storage.Lifecycle;

// Scope selects candidate identities, never revisions. Rank *all* published,
// nonempty revisions of those identities before applying the caller's predicate.
internal static class PrimarySessionRead
{
    internal static string SourceIds(long[] ids) => "logon_source_id IN (" + LifecycleClickHouse.Ids(ids) + ") OR logoff_source_id IN (" + LifecycleClickHouse.Ids(ids) + ")";

    internal static string Select(string columns, string scope, string? predicate = null, string suffix = "") => $$"""
        WITH candidate_sessions AS (
            SELECT session_uid FROM sli_warm.session_lifecycle_revisions WHERE {{scope}}
        ), candidate_batches AS (
            SELECT batch_identity FROM sli_warm.session_lifecycle_revisions
            PREWHERE session_uid IN (SELECT session_uid FROM candidate_sessions)
            WHERE primary_payload_present=1
        ), published_batches AS (
            SELECT batch_identity FROM sli_warm.primary_session_batches
            PREWHERE batch_identity IN (SELECT batch_identity FROM candidate_batches)
            GROUP BY batch_identity HAVING count()=1
        ), ranked_revisions AS (
            SELECT session_uid,revision,revision_sha256,batch_identity,
                max(revision) OVER (PARTITION BY session_uid) AS latest_revision,
                count() OVER (PARTITION BY session_uid,revision) AS revision_rows
            FROM sli_warm.session_lifecycle_revisions
            PREWHERE session_uid IN (SELECT session_uid FROM candidate_sessions)
            WHERE primary_payload_present=1 AND batch_identity IN (SELECT batch_identity FROM published_batches)
        ), selected_revisions AS (
            SELECT session_uid,revision,revision_sha256,batch_identity FROM ranked_revisions
            WHERE revision=latest_revision AND revision_rows=1
        )
        SELECT {{columns}} FROM sli_warm.session_lifecycle_revisions
        PREWHERE (session_uid,revision,revision_sha256,batch_identity) IN (SELECT session_uid,revision,revision_sha256,batch_identity FROM selected_revisions)
        WHERE primary_payload_present=1 AND ({{predicate ?? scope}}){{suffix}}
        """;
}
