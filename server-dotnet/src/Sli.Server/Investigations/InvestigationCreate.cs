using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access.Administration;
using Sli.Server.Auth.Lifecycle;
namespace Sli.Server.Investigations;
public sealed record InvestigationCreateInput(string Title,string? Owner,BigInteger? EventId)
{
    public static BigInteger? ParseEvent(JsonElement payload)
    {
        if(payload.ValueKind!=JsonValueKind.Object || !payload.TryGetProperty("event_db_id",out var value) || value.ValueKind==JsonValueKind.Null)return null;
        return InvestigationEventInput.Parse(payload,false).EventId;
    }
    public static InvestigationCreateInput Parse(JsonElement payload)
    {
        static string Text(JsonElement root,string field,int limit) {
            var item=root.ValueKind==JsonValueKind.Object && root.TryGetProperty(field,out var found)?found:default;
            var clean=AssignmentValidation.Strip(AuthJsonBody.Truthy(item)?InvestigationPythonString.String(item):"");
            return string.Concat(clean.EnumerateRunes().Take(limit).Select(x=>x.ToString()));
        }
        string title=Text(payload,"title",300),owner=Text(payload,"owner",200);
        return new(title,owner.Length==0?null:owner,ParseEvent(payload));
    }
    public void Validate(){if(Title.Length==0)throw new InvestigationException("invalid_title","Investigation title is required");}
}
public interface IInvestigationCreateTransaction
{
    Task LockAsync(CancellationToken ct);
    Task<bool> EventExistsAsync(BigInteger id,CancellationToken ct);
    Task<long> InsertAsync(Guid publicId,string title,string? owner,string actor,CancellationToken ct);
    Task CreatedAuditAsync(long id,string actor,CancellationToken ct);
    Task LinkEventAsync(long id,BigInteger eventId,string actor,CancellationToken ct);
    Task<JsonObject> ReadAsync(long id,CancellationToken ct);
    Task CommitAsync(CancellationToken ct);
}
public static class InvestigationCreate
{
    public static async Task<JsonObject> ExecuteAsync(IInvestigationCreateTransaction tx,InvestigationCreateInput input,string actor,CancellationToken ct)
    {
        input.Validate();
        if(input.EventId is {} eventId) {
            await tx.LockAsync(ct);
            if(!await tx.EventExistsAsync(eventId,ct))throw new InvestigationException("event_not_found",$"Event {eventId} was not found",404);
        }
        long id=await tx.InsertAsync(Guid.NewGuid(),input.Title,input.Owner,actor,ct);
        await tx.CreatedAuditAsync(id,actor,ct);
        if(input.EventId is {} ev)await tx.LinkEventAsync(id,ev,actor,ct);
        var result=await tx.ReadAsync(id,ct);await tx.CommitAsync(ct);return result;
    }
}
