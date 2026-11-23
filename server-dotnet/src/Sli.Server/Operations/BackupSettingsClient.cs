using System.Net.Sockets;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Sli.Server.Operations;

internal sealed record BackupSettingsValues(bool Enabled, string? Path, string? Revision);
internal sealed record BackupSettingsState(BackupSettingsValues Values, string StorageStatus);
internal sealed record BackupSettingsReply(BackupSettingsState? State, string? Error);

internal sealed class BackupSettingsClient
{
    internal const string Invalid = "backup_settings_invalid";
    internal const string Unavailable = "backup_settings_unavailable";
    private const int FrameLimit = 8192;
    private static readonly JsonSerializerOptions RequestOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private static readonly JsonDocumentOptions ResponseOptions = new() { MaxDepth = 4 };
    private static readonly BackupSettingsReply Failed = new(null, Unavailable);

    private readonly Func<CancellationToken, ValueTask<Stream>> connect;

    public BackupSettingsClient() : this(ConnectAsync) { }

    internal BackupSettingsClient(Func<CancellationToken, ValueTask<Stream>> connect) => this.connect = connect;

    internal Task<BackupSettingsReply> GetAsync(CancellationToken ct) =>
        RequestAsync(new { action = "get" }, ct);

    internal Task<BackupSettingsReply> SetAsync(BackupSettingsValues values, CancellationToken ct) =>
        RequestAsync(new { action = "set", enabled = values.Enabled, path = values.Path, revision = values.Revision }, ct);

    internal static int? ErrorStatus(string? error) => error switch
    {
        "backup_settings_revision_conflict" => 409,
        Unavailable => 503,
        Invalid or "native_backup_root_invalid" or "native_backup_root_untrusted" or
            "native_backup_root_same_device" or "native_backup_root_insufficient_space" or
            "native_backup_root_mount_mismatch" => 400,
        _ => null,
    };

    internal static BackupSettingsValues? ReadUpdate(JsonElement json) =>
        HasFields(json, "enabled", "path", "revision") ? ReadValues(json) : null;

    private static bool HasFields(JsonElement json, params string[] names) =>
        json.ValueKind == JsonValueKind.Object && json.EnumerateObject().Count() == names.Length
        && names.All(name => json.TryGetProperty(name, out _));

    private static BackupSettingsValues? ReadValues(JsonElement json)
    {
        try
        {
            var enabled = json.GetProperty("enabled");
            var path = json.GetProperty("path");
            var revision = json.GetProperty("revision");
            if (enabled.ValueKind is not (JsonValueKind.True or JsonValueKind.False)
                || path.ValueKind is not (JsonValueKind.String or JsonValueKind.Null)
                || revision.ValueKind != JsonValueKind.String) return null;
            bool isEnabled = enabled.GetBoolean();
            string? selectedPath = path.GetString();
            string token = revision.GetString()!;
            if (selectedPath is null ? isEnabled :
                !selectedPath.StartsWith('/') || Encoding.UTF8.GetByteCount(selectedPath) > 4096
                || selectedPath.Any(char.IsControl)) return null;
            if (token.Length is < 1 or > 128
                || token.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('.' or '_' or '-')))
                return null;
            return new(isEnabled, selectedPath, token);
        }
        catch (InvalidOperationException)
        {
            // JSON escaped text may contain an invalid UTF-16 scalar.
            return null;
        }
    }

    private static BackupSettingsReply ParseResponse(ReadOnlyMemory<byte> body)
    {
        using var document = JsonDocument.Parse(body, ResponseOptions);
        var json = document.RootElement;
        if (HasFields(json, "ok", "error") && json.GetProperty("ok").ValueKind == JsonValueKind.False
            && json.GetProperty("error").ValueKind == JsonValueKind.String)
        {
            var error = json.GetProperty("error").GetString();
            return ErrorStatus(error) is null ? Failed : new(null, error);
        }
        if (!HasFields(json, "ok", "enabled", "path", "revision", "storage_status")
            || json.GetProperty("ok").ValueKind != JsonValueKind.True
            || json.GetProperty("storage_status").ValueKind != JsonValueKind.String
            || ReadValues(json) is not { } values) return Failed;
        string status = json.GetProperty("storage_status").GetString()!;
        return status is "ready" or "unconfigured" or "unavailable" ? new(new(values, status), null) : Failed;
    }

    private async Task<BackupSettingsReply> RequestAsync(object request, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(request, RequestOptions);
            if (bytes.Length >= FrameLimit) return new(null, Invalid);
            using var stream = await connect(deadline.Token);
            await stream.WriteAsync(bytes, deadline.Token);
            await stream.WriteAsync("\n"u8.ToArray(), deadline.Token);

            byte[] buffer = new byte[FrameLimit];
            int used = 0;
            while (used < buffer.Length)
            {
                int size = await stream.ReadAsync(buffer.AsMemory(used), deadline.Token);
                if (size == 0) return Failed;
                int lineEnd = Array.IndexOf(buffer, (byte)'\n', used, size);
                used += size;
                if (lineEnd >= 0)
                    return lineEnd == used - 1 ? ParseResponse(buffer.AsMemory(0, lineEnd)) : Failed;
            }
            return Failed;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error) when (error is SocketException or IOException or JsonException
            or NotSupportedException or OperationCanceledException or InvalidOperationException or UnauthorizedAccessException)
        {
            return Failed;
        }
    }

    private static async ValueTask<Stream> ConnectAsync(CancellationToken ct)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint("/run/sli/backup-settings/control.sock"), ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
