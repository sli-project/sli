using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Hosting;

namespace Sli.Server.Notifications;

public static class NotificationSetupCommand
{
    [StructLayout(LayoutKind.Sequential)] private struct Group { public IntPtr Name; public IntPtr Password; public uint Id; public IntPtr Members; }
    [DllImport("libc", EntryPoint = "getgrnam")] private static extern IntPtr GetGroup(string name);
    public static async Task RefreshDeliveryAsync(string action, bool native, CancellationToken ct)
    {
        if (!native || action is not ("token" or "bind" or "smtp_save")) return;
        var start = new ProcessStartInfo("/usr/bin/systemctl") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add("restart"); start.ArgumentList.Add("sli-dotnet-notification-delivery.service");
        start.Environment.Clear(); start.Environment["PATH"] = "/usr/bin:/bin"; start.Environment["LC_ALL"] = "C";
        using var process = Process.Start(start) ?? throw NotificationException.Setup("telegram_setup_unavailable");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(90));
        var stdout = process.StandardOutput.ReadToEndAsync(deadline.Token); var stderr = process.StandardError.ReadToEndAsync(deadline.Token);
        try { await process.WaitForExitAsync(deadline.Token); await Task.WhenAll(stdout, stderr); }
        catch { try { process.Kill(true); } catch { } throw NotificationException.Setup("telegram_setup_unavailable"); }
        if (process.ExitCode != 0) throw NotificationException.Setup("telegram_setup_unavailable");
    }
    public static async Task ServeAsync(Socket listener, NotificationSetupService service, bool native, CancellationToken ct)
    {
        // Serial requests preserve the same candidate/file ordering as UnixStreamServer.
        while (!ct.IsCancellationRequested)
        {
            using var client = await listener.AcceptAsync(ct); using var stream = new NetworkStream(client, false);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
            JsonObject response;
            try
            {
                var raw = await NotificationSetupClient.ReadLineAsync(stream, deadline.Token); if (raw.Length == 0) continue;
                var body = JsonNode.Parse(raw)!.AsObject(); response = await service.HandleAsync(body, deadline.Token);
                await RefreshDeliveryAsync(body["action"]?.ToString() ?? "", native, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (NotificationException ex) { response = new JsonObject { ["error"] = ex.Code }; }
            catch { response = new JsonObject { ["error"] = "telegram_setup_unavailable" }; }
            try { await stream.WriteAsync(JsonSerializer.SerializeToUtf8Bytes(response), deadline.Token); await stream.WriteAsync(new byte[] { 10 }, deadline.Token); }
            catch (Exception) when (!ct.IsCancellationRequested) { /* Closed/timed-out clients cannot stop the writer. */ }
        }
    }
    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length != 0) { Console.Error.WriteLine("notification_setup_arguments_invalid"); return 1; }
        if (!OperatingSystem.IsLinux()) { Console.Error.WriteLine("notification_setup_root_required:platform"); return 1; }
        string? path = null; bool bound = false;
        string step = "SLI_TELEGRAM_SECRET_DIR";
        try
        {
            bool native = Environment.GetEnvironmentVariable("SLI_NATIVE_NOTIFICATION_SETUP") == "1";
            var files = new NotificationSetupFiles(Environment.GetEnvironmentVariable("SLI_TELEGRAM_SECRET_DIR") ?? "/var/lib/notification-secrets");
            var setup = new NotificationSetupService(files, new NotificationSetupBot(), Environment.GetEnvironmentVariable("SLI_PUBLIC_URL") ?? "", native,
                Environment.GetEnvironmentVariable("SLI_NOTIFICATION_PROXY") ?? "");
            path = Environment.GetEnvironmentVariable("SLI_TELEGRAM_SETUP_SOCKET") ?? "/run/notification-setup/control.sock";
            step = "sli_api_group";
            uint gid = 10001;
            if (native) { var group = GetGroup("sli-api"); if (group == IntPtr.Zero) throw new IOException(); gid = Marshal.PtrToStructure<Group>(group).Id; }
            step = "SLI_TELEGRAM_SETUP_SOCKET:prepare_directory"; NotificationSetupFiles.PrepareSocket(path, gid);
            using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            step = "SLI_TELEGRAM_SETUP_SOCKET:bind"; listener.Bind(new UnixDomainSocketEndPoint(path)); bound = true;
            step = "SLI_TELEGRAM_SETUP_SOCKET:protect"; NotificationSetupFiles.Protect(path, gid, (UnixFileMode)0x1b0); listener.Listen(16);
            step = "serve";
            return await WorkerShutdown.RunAsync(async stop =>
            {
                await ServeAsync(listener, setup, native, stop);
                return 0;
            });
        }
        catch (Exception error) { Console.Error.WriteLine("notification_setup_unavailable:" + WorkerFailure.Describe(error, step)); return 1; }
        finally { if (bound && path is not null) try { File.Delete(path); } catch { } }
    }
}
