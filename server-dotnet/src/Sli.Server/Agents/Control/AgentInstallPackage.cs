using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Sli.Server.Agents.Control;

internal static class AgentInstallPackage
{
    internal static async Task<string> DigestAsync(string path, CancellationToken ct)
    {
        await using var file = File.OpenRead(path);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(file, ct));
    }

    internal static async Task<Dictionary<string, string>> ExportPropertiesAsync(string path, CancellationToken ct) =>
        (await ReadPropertyTableAsync(path, ct)).Properties;

    private static async Task<(string Header, Dictionary<string, string> Properties)> ReadPropertyTableAsync(string path, CancellationToken ct)
    {
        var rows = (await RunAsync("msiinfo", ["export", path, "Property"], ct)).Split('\n');
        if (rows.Length < 4 || rows[0].TrimEnd('\r') != "Property\tValue")
            throw new InvalidDataException("Invalid MSI Property table.");
        var properties = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string row in rows.Skip(3))
        {
            if (row.Length == 0) continue;
            var fields = row.TrimEnd('\r').Split('\t', 2);
            if (fields.Length != 2 || !properties.TryAdd(fields[0], fields[1]))
                throw new InvalidDataException("Invalid MSI Property row.");
        }
        return (string.Join("\r\n", rows.Take(3).Select(row => row.TrimEnd('\r'))), properties);
    }

    internal static async Task BuildAsync(string source, string output, AgentConsolePackage settings, string token, CancellationToken ct)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        string table = Path.Combine(Path.GetDirectoryName(output)!, "Property.idt");
        bool copied = false, exported = false;
        try
        {
            await using (var input = File.OpenRead(source))
            await using (var copy = new FileStream(output, new FileStreamOptions {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            }))
            {
                copied = true;
                await input.CopyToAsync(copy, ct);
            }
            if (await DigestAsync(output, ct) != settings.Digest)
                throw new InvalidDataException("Agent MSI release digest mismatch.");
            var (header, properties) = await ReadPropertyTableAsync(output, ct);
            if (!properties.TryGetValue("ProductName", out var product))
                throw new InvalidDataException("The release MSI has no product name.");
            if (!properties.TryGetValue("ProductVersion", out var version) || version != settings.ProductVersion)
                throw new InvalidDataException("The release MSI version does not match its manifest.");
            if (properties.ContainsKey("ENROLL_TOKEN"))
                throw new InvalidDataException("The release MSI contains enrollment material.");
            var name = settings.Origin.IdnHost;
            string productName = $"{product} ({name[..Math.Min(name.Length, 40)]})";
            properties["ProductName"] = productName;
            // A distinct product lets plain msiexec /i run the same-version major upgrade.
            properties["ProductCode"] = Guid.NewGuid().ToString("B").ToUpperInvariant();
            properties["SERVER_URL"] = settings.Origin.AbsoluteUri;
            properties["CA_FINGERPRINT"] = settings.Pin;
            properties["SERVER_CA"] = settings.Root;
            properties["ENROLL_TOKEN"] = token;
            await using (var idt = new FileStream(table, new FileStreamOptions {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            }))
            await using (var writer = new StreamWriter(idt, new UTF8Encoding(false)))
            {
                exported = true;
                writer.NewLine = "\r\n";
                await writer.WriteLineAsync(header.AsMemory(), ct);
                foreach (var (key, value) in properties)
                    await writer.WriteLineAsync($"{key}\t{value}".AsMemory(), ct);
            }
            // A changed MSI also needs a fresh PackageCode. Preserve UpgradeCode and ProductVersion.
            await RunAsync("msibuild", [output, "-i", table, "-s", productName, "SLI", "x64;1033", Guid.NewGuid().ToString("B").ToUpperInvariant()], ct);
            File.SetUnixFileMode(output, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var written = await ExportPropertiesAsync(output, ct);
            if (properties.Any(pair => !written.TryGetValue(pair.Key, out var value) || value != pair.Value))
                throw new InvalidDataException("The personalized MSI properties did not round-trip.");
            using var durable = new FileStream(output, FileMode.Open, FileAccess.Write, FileShare.None);
            durable.Flush(flushToDisk: true);
        }
        catch
        {
            if (copied) File.Delete(output);
            throw;
        }
        finally { if (exported) File.Delete(table); }
    }

    private static async Task<string> RunAsync(string name, string[] arguments, CancellationToken ct)
    {
        var start = new ProcessStartInfo("/usr/bin/" + name) {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        Process process;
        try { process = Process.Start(start) ?? throw new IOException("MSI tool did not start."); }
        catch (Win32Exception) { throw new IOException("MSI tool did not start."); }
        using (process)
        {
            // The export can contain the key. Tool output must never enter logs or errors.
            var output = process.StandardOutput.ReadToEndAsync(ct);
            var errors = process.StandardError.ReadToEndAsync(ct);
            try { await process.WaitForExitAsync(ct); }
            catch (OperationCanceledException)
            {
                if (!process.HasExited) process.Kill();
                await process.WaitForExitAsync(CancellationToken.None);
                throw;
            }
            await Task.WhenAll(output, errors);
            if (process.ExitCode != 0) throw new InvalidDataException("MSI tool failed: " + name);
            return await output;
        }
    }
}
