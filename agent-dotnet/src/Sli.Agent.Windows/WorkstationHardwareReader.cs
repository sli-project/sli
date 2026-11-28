using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Core;

namespace Sli.Agent.Windows;

public static class WorkstationHardwareReader
{
    // Fixed local queries. Only the explicit hardware fields below leave PowerShell.
    private const string Query = """
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
        function Read-List($query) {
            try { return ,@(& $query) } catch { return $null }
        }
        function Read-Text($bytes) {
            if ($null -ne $bytes) { return (-join ($bytes | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ })).Trim() }
        }
        function Disk-Identity($disk) {
            if ($disk.SerialNumber -and $disk.SerialNumber.Trim() -notmatch '^(0+|Unknown|None|Default string)$') { return $disk.SerialNumber.Trim() }
            return $disk.PNPDeviceID
        }
        $computer = Read-List { Get-CimInstance Win32_ComputerSystem | Select-Object -First 1 }
        $bios = Read-List { Get-CimInstance Win32_BIOS | Select-Object -First 1 }
        $modules = Read-List { Get-CimInstance Win32_PhysicalMemory | Select-Object -First 65 }
        $drives = Read-List { Get-CimInstance Win32_DiskDrive | Select-Object -First 33 }
        $physical = Read-List { Get-CimInstance -Namespace root/Microsoft/Windows/Storage -ClassName MSFT_PhysicalDisk | Select-Object -First 33 }
        $diskNumbers = Read-List { Get-Disk | Select-Object -First 33 }
        $partitions = Read-List { Get-Partition | Select-Object -First 65 }
        $tpm = try { Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm | Select-Object -First 1 } catch { $null }
        $tpmEnabled = if ($tpm) {
            try { $result = Invoke-CimMethod -InputObject $tpm -MethodName IsEnabled; if ($result.ReturnValue -eq 0) { $result.IsEnabled } }
            catch { $tpm.IsEnabled_InitialValue }
        }
        $secureBoot = try { Confirm-SecureBootUEFI } catch { $null }
        $system = $null
        $firmware = $null
        $serial = $null
        if ($bios.Count -eq 1) {
            $serial = $bios[0].SerialNumber
            $date = if ($bios[0].ReleaseDate) { $bios[0].ReleaseDate.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
            $firmware = @(@{version=$bios[0].SMBIOSBIOSVersion; date=$date})
        }
        if ($computer.Count -eq 1) {
            $system = @(@{manufacturer=$computer[0].Manufacturer; model=$computer[0].Model; serial=$serial})
        }
        $snapshot = [ordered]@{
            computer = $system;
            bios = $firmware;
            security = @(@{secure_boot=$secureBoot; tpm_enabled=$tpmEnabled; tpm_version=if ($tpm.SpecVersion) { ($tpm.SpecVersion -split ',')[0].Trim() }});
            processor = Read-List { Get-CimInstance Win32_Processor | Select-Object -First 17 | ForEach-Object {
                @{id=$_.DeviceID; model=$_.Name; cores=$_.NumberOfCores; threads=$_.NumberOfLogicalProcessors}
            }};
            memory = if ($computer.Count -eq 1) { ,@(@{size=if ($modules.Count -gt 0 -and $modules.Count -le 64 -and @($modules | Where-Object { -not $_.Capacity }).Count -eq 0) {
                [uint64](($modules | Measure-Object -Property Capacity -Sum).Sum)
            } else { $computer[0].TotalPhysicalMemory }}) };
            memory_module = if ($null -ne $modules) { ,@($modules | ForEach-Object {
                $slot = ($_.BankLabel + ' ' + $_.DeviceLocator).Trim()
                @{id=$slot; slot=$slot; size=$_.Capacity; speed=if ($_.ConfiguredClockSpeed) {$_.ConfiguredClockSpeed} else {$_.Speed}; manufacturer=$_.Manufacturer; serial=$_.SerialNumber}
            }) };
            disk = if ($null -ne $drives) { ,@($drives | ForEach-Object {
                $disk = $_
                $match = @($physical | Where-Object { $disk.SerialNumber -and $_.SerialNumber -and $_.SerialNumber.Trim() -eq $disk.SerialNumber.Trim() })
                $kind = if ($match.Count -eq 1) { switch ($match[0].MediaType) { 3 {'HDD'} 4 {'SSD'} } }
                $number = $diskNumbers | Where-Object { $_.Number -eq $disk.Index } | Select-Object -First 1
                $bus = switch ($number.BusType) { 3 {'ATA'} 7 {'USB'} 10 {'SAS'} 11 {'SATA'} 12 {'SD'} 17 {'NVMe'} }
                @{id=(Disk-Identity $disk); model=$disk.Model; size=$disk.Size; type=$kind; interface=if ($bus) {$bus} else {$disk.InterfaceType}; serial=$disk.SerialNumber}
            }) };
            volume = Read-List { Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume | Select-Object -First 65 | ForEach-Object {
                $volume = $_
                $status = try { $result = Invoke-CimMethod -InputObject $volume -MethodName GetProtectionStatus
                    if ($result.ReturnValue -eq 0) { $result.ProtectionStatus } } catch { $null }
                $part = $partitions | Where-Object { ($volume.DriveLetter -and ('{0}:' -f $_.DriveLetter) -eq $volume.DriveLetter) -or $_.AccessPaths -contains $volume.DeviceID } | Select-Object -First 1
                $disk = if ($null -ne $part) { $drives | Where-Object { $_.Index -eq $part.DiskNumber } | Select-Object -First 1 }
                @{id=$volume.DeviceID; disk_id=if ($disk) { Disk-Identity $disk }; mount=$volume.DriveLetter; partition=$part.PartitionNumber;
                  system=[bool]($volume.DriveLetter -and $volume.DriveLetter -eq $env:SystemDrive);
                  bitlocker=switch ($status) { 0 {'off'} 1 {'on'} }}
            }};
            video = Read-List { Get-CimInstance Win32_VideoController | Select-Object -First 17 | ForEach-Object {
                @{id=$_.PNPDeviceID; model=$_.Name}
            }};
            network = Read-List { Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=true' | Select-Object -First 33 | ForEach-Object {
                $mac = if ($_.MACAddress) { $_.MACAddress.ToUpperInvariant() }
                @{id=if ($mac) { $mac } else { $_.PNPDeviceID }; name=$_.Name; mac=$mac; speed=$_.Speed}
            }};
            monitor = Read-List { Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorID | Where-Object Active | Select-Object -First 17 | ForEach-Object {
                $serial = Read-Text $_.SerialNumberID
                $model = Read-Text $_.UserFriendlyName
                if (-not $model) { $model = Read-Text $_.ProductCodeID }
                @{id=$_.InstanceName; model=$model; serial=$serial}
            }}
        }
        $snapshot | ConvertTo-Json -Compress -Depth 5
        """;

    [SupportedOSPlatform("windows")]
    public static async Task<JsonObject?> ReadAsync(CancellationToken ct)
    {
        const int outputLimit = 512 * 1024;
        var executable = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        using var process = new Process { StartInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
        } };
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-Command", Query })
            process.StartInfo.ArgumentList.Add(argument);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        var started = false;
        try
        {
            started = process.Start();
            if (!started) return null;
            var errors = process.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
            var output = new StringBuilder();
            var buffer = new char[4096];
            while (await process.StandardOutput.ReadAsync(buffer.AsMemory(), deadline.Token) is > 0 and var count)
            {
                if (output.Length + count > outputLimit) return null;
                output.Append(buffer, 0, count);
            }
            await Task.WhenAll(errors, process.WaitForExitAsync(deadline.Token));
            return process.ExitCode == 0 && JsonNode.Parse(output.ToString()) is JsonObject data ? WorkstationHardware.Build(data) : null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return null; }
        catch (Exception error) when (error is Win32Exception or IOException or UnauthorizedAccessException or InvalidOperationException or JsonException)
        { return null; }
        finally
        {
            deadline.Cancel();
            if (started)
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
                catch (Exception error) when (error is Win32Exception or InvalidOperationException or NotSupportedException) { }
            }
        }
    }
}
