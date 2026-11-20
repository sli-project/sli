using System.Numerics;
using System.Text.Json;
using Sli.Server.Access.Administration;
using Sli.Server.Auth.Lifecycle;
namespace Sli.Server.Investigations;
public sealed record InvestigationEventInput(BigInteger EventId,string Relation)
{
    public static InvestigationEventInput Parse(JsonElement payload,bool add)
    {
        if(payload.ValueKind!=JsonValueKind.Object || !payload.TryGetProperty("event_db_id",out var raw))throw new InvestigationException("invalid_event_db_id","invalid_event_db_id");
        BigInteger id;
        try {id=AssignmentValidation.Integer(raw);}
        catch(Exception e) when(e is InvalidOperationException or ArgumentException or AuthInputException or AssignmentValidationException or FormatException){throw new InvestigationException("invalid_event_db_id","invalid_event_db_id");}
        string relation="confirmed";
        if(add && payload.TryGetProperty("relation_status",out var item) && AuthJsonBody.Truthy(item))relation=InvestigationPythonString.String(item).ToLowerInvariant();
        return new(id,relation);
    }
    public void Validate(){if(Relation is not ("confirmed" or "excluded"))throw new InvestigationException("invalid_relation_status","Relation status must be confirmed or excluded");}
}
public sealed record InvestigationEventRow(long EventDbId,string RelationStatus,string AddedBy,string AddedAt);
public sealed record InvestigationEventResult(InvestigationEventRow Row,bool Replay);
public interface IInvestigationEventTransaction
{
    Task LockAsync(CancellationToken ct);
    Task<long> ReadCaseAsync(InvestigationIdentity identity,CancellationToken ct);
    Task<bool> EventExistsAsync(BigInteger id,CancellationToken ct);
    Task<InvestigationEventRow?> InsertAsync(long id,BigInteger ev,string relation,string actor,CancellationToken ct);
    Task<InvestigationEventRow?> ReadExistingAsync(long id,BigInteger ev,CancellationToken ct);
    Task<bool> DeleteAsync(long id,BigInteger ev,CancellationToken ct);
    Task UpdateAndAuditAsync(long id,BigInteger ev,string? relation,string actor,CancellationToken ct);
    Task CommitAsync(CancellationToken ct);
}
public static class InvestigationEventMutation
{
    public static async Task<InvestigationEventResult> AddAsync(IInvestigationEventTransaction tx,InvestigationIdentity identity,InvestigationEventInput input,string actor,CancellationToken ct)
    {
        input.Validate();await tx.LockAsync(ct);long id=await tx.ReadCaseAsync(identity,ct);
        if(!await tx.EventExistsAsync(input.EventId,ct))throw new InvestigationException("event_not_found",$"Event {input.EventId} was not found",404);
        var row=await tx.InsertAsync(id,input.EventId,input.Relation,actor,ct);
        if(row is null) {
            var existing=await tx.ReadExistingAsync(id,input.EventId,ct);
            if(existing is null || existing.RelationStatus!=input.Relation)throw new InvestigationException("conflict","Evidence already exists with a different relation status",409);
            await tx.CommitAsync(ct);return new(existing,true);
        }
        await tx.UpdateAndAuditAsync(id,input.EventId,input.Relation,actor,ct);await tx.CommitAsync(ct);return new(row,false);
    }
    public static async Task RemoveAsync(IInvestigationEventTransaction tx,InvestigationIdentity identity,BigInteger eventId,string actor,CancellationToken ct)
    {
        long id=await tx.ReadCaseAsync(identity,ct);
        if(!await tx.DeleteAsync(id,eventId,ct))throw new InvestigationException("not_found","Investigation evidence was not found",404);
        await tx.UpdateAndAuditAsync(id,eventId,null,actor,ct);await tx.CommitAsync(ct);
    }
}
