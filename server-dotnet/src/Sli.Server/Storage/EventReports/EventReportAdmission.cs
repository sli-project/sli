using System.Text.Json.Nodes;

namespace Sli.Server.Storage.EventReports;
internal static class EventReportAdmission
{
    internal static async Task<Dictionary<long,JsonObject>> ReadAsync(long[] ids,Func<long,CancellationToken,Task<bool>> admitted,
        Func<long[],CancellationToken,Task<Dictionary<long,JsonObject>>> hydrate,CancellationToken ct)
    {
        var permitted=new List<long>();
        foreach(long id in ids) { ct.ThrowIfCancellationRequested(); if(await admitted(id,ct)) permitted.Add(id); }
        if(permitted.Count==0) return [];
        var result=await hydrate(permitted.ToArray(),ct);
        if(result.Keys.Any(id=>!permitted.Contains(id))) throw new InvalidDataException("unauthorized_hydration_result");
        return result;
    }
}
