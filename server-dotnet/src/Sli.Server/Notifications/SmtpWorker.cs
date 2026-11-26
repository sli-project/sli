using System.Text.Json;
using Npgsql;
using Sli.Server.Problems;
namespace Sli.Server.Notifications;
public sealed class SmtpWorker(NotificationDatabase database,SmtpSender sender,ILogger<SmtpWorker> logger)
{
    public const string ClaimSql="""
        with candidate as (
          select id,state from notification_outbox where
           ((state in ('pending','retry') and available_at<=clock_timestamp()) or (state='sending' and lease_until<=clock_timestamp()))
           and channel='smtp' and object_kind in ('test_problem','semantic_finding','report_schedule')
          order by created_at,id for update skip locked limit 1)
        update notification_outbox j set state='sending',lease_token=@token,lease_until=clock_timestamp()+interval '60 seconds',
          attempts=attempts+1,updated_at=clock_timestamp() from candidate where j.id=candidate.id
        returning j.id,j.subscription_id,j.subscription_revision,j.object_kind,j.object_id,j.recipient_user_id,j.attempts,j.lease_token,j.created_at,j.object_severity,j.delivery_reason,j.delay_minutes,
          candidate.state='sending' and j.object_kind='semantic_finding'
        """;
    public async Task<bool> ProcessAsync(CancellationToken ct)
    {
        NotificationJob? job;
        await using(var db=await database.OpenAsync(ct)) {
            await using var tx=await db.BeginTransactionAsync(ct);
            await using var cmd=new NpgsqlCommand(ClaimSql,db,tx);cmd.Parameters.AddWithValue("token",Guid.NewGuid());
            await using(var r=await cmd.ExecuteReaderAsync(ct)) {
                if(!await r.ReadAsync(ct))job=null;
                else job=new(r.GetGuid(0),r.GetGuid(1),r.GetInt64(2),r.GetString(3),r.GetGuid(4),r.GetInt64(5),r.GetInt32(6),r.GetGuid(7),r.GetDateTime(8),r.IsDBNull(9)?null:r.GetString(9),r.GetString(10),r.GetInt32(11)) { Abandoned=r.GetBoolean(12) };
            }
            await tx.CommitAsync(ct);
        }
        if(job is null)return false;
        return await ProcessClaimedAsync(job,ct);
    }
    public async Task<bool> ProcessClaimedAsync(NotificationJob job,CancellationToken ct)
    {
        job=job with {Channel="smtp"};
        // Finish a claimed dispatch and its fenced DB transaction on shutdown.
        ct=CancellationToken.None;
        await using(var db=await database.OpenAsync(ct)) {
            await using var tx=await db.BeginTransactionAsync(ct);
            JsonElement? prepared=null;bool preparationFailed=false;
            if(job.Kind=="report_schedule") {
                await tx.SaveAsync("report_prepare",ct);
                try {prepared=await ReportScheduleDelivery.LoadAsync(db,tx,job,ct);}
                catch {await tx.RollbackAsync("report_prepare",ct);preparationFailed=true;}
            }
            long owner=0;bool valid=false;
            await using(var cmd=new NpgsqlCommand("select owner_user_id,recipient_user_id,revision,enabled,channel from notification_subscriptions where id=@id for share",db,tx)) {
                cmd.Parameters.AddWithValue("id",job.Subscription);await using var r=await cmd.ExecuteReaderAsync(ct);
                if(await r.ReadAsync(ct)){owner=r.GetInt64(0);valid=r.GetInt64(1)==job.Recipient && r.GetInt64(2)==job.Revision && r.GetBoolean(3) && r.GetString(4)=="smtp";}
            }
            await using(var cmd=new NpgsqlCommand("select id from notification_outbox where id=@id and state='sending' and lease_token=@token and lease_until>clock_timestamp() for update",db,tx)) {
                cmd.Parameters.AddWithValue("id",job.Id);cmd.Parameters.AddWithValue("token",job.Lease);
                if(await cmd.ExecuteScalarAsync(ct) is null){await tx.CommitAsync(ct);return true;}
            }
            string state=job.Kind=="report_schedule"?"blocked":"cancelled",code=job.Kind=="report_schedule"?"recipient_denied":"subscription_changed";int retryAfter=0;bool internalSendError=false,recorded=false;
            ProblemAccess? recipientAccess = null;
            // The previous process may have reached the provider before it stopped.
            if(job.Abandoned) {state="delivery_unknown";code="smtp_outcome_unknown";}
            else if(valid) {
                try {
                    if(job.Kind=="report_schedule") {
                        if(preparationFailed)throw new InvalidOperationException();
                        if(prepared is null){valid=false;state="blocked";code="recipient_denied";}
                        else {job=await ReportScheduleDelivery.AuthorizeAsync(database,job,prepared.Value,ct);state="";code="";}
                    } else {var recipientOwner=await NotificationAlert.QueueAccessAsync(database,owner,ct);
                        valid=recipientOwner is not null;
                        if(valid) recipientAccess=owner==job.Recipient ? recipientOwner : await NotificationAlert.QueueAccessAsync(database,job.Recipient,ct);
                        valid=recipientAccess is not null;state=valid?"":"blocked";code=valid?"":"recipient_denied";}
                }
                catch(Exception e) when(e is UnauthorizedAccessException or FormatException){valid=false;state="blocked";code="recipient_denied";}
                catch(OperationCanceledException) when(ct.IsCancellationRequested){throw;}
                catch {valid=false;state="retry";code="access_unavailable";}
                if(valid) {
                    try {
                        bool enabled=false;string? secret=null,tls=null;long channelRevision=0;
                        await using(var cmd=new NpgsqlCommand("select enabled,tls_mode,secret_ref,revision from notification_channels where kind='smtp' for share",db,tx)) {
                            await using var r=await cmd.ExecuteReaderAsync(ct);if(await r.ReadAsync(ct)){enabled=r.GetBoolean(0);tls=r.GetString(1);secret=r.GetString(2);channelRevision=r.GetInt64(3);}
                        }
                        if(job.ReportChannelRevision is {} expectedRevision && expectedRevision!=channelRevision)throw new UnauthorizedAccessException();
                        if(!enabled || tls is not ("tls" or "starttls") || secret!="SLI_NOTIFY_SMTP_PASSWORD")code="smtp_not_configured";
                        else {
                            SmtpSettings? settings=null;string? text=null;
                            try {settings=SmtpSettingsReader.Read(job.Recipient,channelRevision,Environment.GetEnvironmentVariable,ReadBounded);}
                            catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or ArgumentException or FormatException or JsonException or InvalidOperationException or System.Text.DecoderFallbackException){}
                            if(settings is not null) text=await NotificationAlert.FormatAsync(db,tx,job,settings.BaseUrl,recipientAccess,null,ct);
                            if(settings is null || text is null)code="smtp_not_configured";
                            else {var outcome=await sender.SendAsync(settings,tls,job,text,ct);code=outcome.Code;internalSendError=outcome.InternalError;}
                        }
                        state=SmtpOutcome.State(code);
                    }
                    catch(OperationCanceledException) when(ct.IsCancellationRequested){throw;}
                    catch(UnauthorizedAccessException){state="blocked";code="recipient_denied";}
                    catch {state="retry";code="transport_unavailable";}
                }
            }
            (state,int delay)=Completion(state,job.Attempts,retryAfter);
            await using(var done=new NpgsqlCommand("update notification_outbox set state=@state,result_code=@code,lease_token=null,lease_until=null,available_at=clock_timestamp()+(@delay * interval '1 second'),updated_at=clock_timestamp() where id=@id and state='sending' and lease_token=@token returning id",db,tx)) {
                done.Parameters.AddWithValue("state",state);done.Parameters.AddWithValue("code",code);done.Parameters.AddWithValue("delay",delay);done.Parameters.AddWithValue("id",job.Id);done.Parameters.AddWithValue("token",job.Lease);
                if(await done.ExecuteScalarAsync(ct) is not null) {
                    recorded=true;
                    await using var attempt=new NpgsqlCommand("insert into notification_attempts(job_id,attempt,state,result_code) values(@id,@attempt,@state,@code)",db,tx);
                    attempt.Parameters.AddWithValue("id",job.Id);attempt.Parameters.AddWithValue("attempt",job.Attempts);attempt.Parameters.AddWithValue("state",state);attempt.Parameters.AddWithValue("code",code);await attempt.ExecuteNonQueryAsync(ct);
                }
            }
            await tx.CommitAsync(ct);
            if(internalSendError && recorded) {try {logger.LogError("smtp_send_internal_error");} catch {}}
        }
        return true;
    }
    public static (string State,int Delay) Completion(string state,int attempt,int retryAfter)
    {
        if(attempt<1 || retryAfter<0)throw new ArgumentOutOfRangeException();
        int[] delays=[60,300,900,3600];return (state=="retry" && attempt>=5 ? "failed" : state,Math.Max(delays[Math.Min(attempt-1,3)],retryAfter));
    }
        private static byte[] ReadBounded(string path){using var f=File.OpenRead(path);var b=new byte[65537];int n=0,k;while(n<b.Length && (k=f.Read(b,n,b.Length-n))>0)n+=k;if(n>65536)throw new FormatException();return b[..n];}
}
