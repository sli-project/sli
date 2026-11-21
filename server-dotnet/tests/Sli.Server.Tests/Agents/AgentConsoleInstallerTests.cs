using System.Diagnostics;
using Sli.Server.Agents.Control;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentConsoleInstallerTests
{
    [Theory]
    [InlineData("success")]
    [InlineData("failure")]
    public async Task Generated_command_updates_in_place_and_recovers_from_an_msi_failure(string outcome)
    {
        var shell = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
            : (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator)
                .Where(Path.IsPathFullyQualified).Select(directory => Path.Combine(directory, "pwsh")).FirstOrDefault(File.Exists);
        Assert.SkipWhen(shell is null || !File.Exists(shell), "PowerShell is required for the generated installer command test");

        var ct = TestContext.Current.CancellationToken;
        var temporary = Directory.CreateTempSubdirectory("sli-agent-update-");
        try
        {
            string commandPath = Path.Combine(temporary.FullName, "command.ps1");
            string testPath = Path.Combine(temporary.FullName, "update-test.ps1");
            var package = new AgentConsolePackage(new Uri("https://agents.example.test/"), "test-ca", "test-pin", "test-digest");
            await File.WriteAllTextAsync(commandPath, package.Command("synthetic-token"), ct);
            await File.WriteAllTextAsync(testPath, UpdateScenario, ct);

            var start = new ProcessStartInfo(shell!)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            };
            foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-File", testPath, commandPath, outcome })
                start.ArgumentList.Add(argument);
            using var process = Process.Start(start)!;
            var output = process.StandardOutput.ReadToEndAsync(ct);
            var error = process.StandardError.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);
            Assert.True(process.ExitCode == 0, $"{await output}\n{await error}");
        }
        finally { temporary.Delete(recursive: true); }
    }

    private const string UpdateScenario = """
        param($CommandPath, $Outcome)
        $ErrorActionPreference = 'Stop'
        Set-StrictMode -Version Latest

        # Exercise the functions emitted in the install command without running its
        # administrator, network, registry or Windows service operations on the test host.
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($CommandPath, [ref]$null, [ref]$parseErrors)
        if ($parseErrors) { throw ($parseErrors -join "`n") }
        foreach ($definition in $ast.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -in 'Update-InstalledAgent', 'Copy-AgentState', 'Remove-LegacyAgent'
        }, $true)) {
            . ([scriptblock]::Create($definition.Extent.Text))
        }

        $state = Join-Path $PSScriptRoot 'state'
        $work = Join-Path $PSScriptRoot 'work'
        $msi = Join-Path $work 'SliAgent.msi'
        $identity = Join-Path $state 'identity.json'
        [void][IO.Directory]::CreateDirectory((Join-Path $state 'queue'))
        [void][IO.Directory]::CreateDirectory($work)
        $cursor = Join-Path (Join-Path $state 'queue') 'cursor.json'
        [IO.File]::WriteAllText($identity, 'previous identity')
        [IO.File]::WriteAllText($cursor, 'previous cursor')
        $script:running = $true
        $script:invoked = $false

        function Assert-AgentMsiUpgrade($Msi, $Product) {}
        function Assert-PrivateDirectory($Path) {}
        function New-PrivateDirectory($Path) { [void][IO.Directory]::CreateDirectory($Path) }
        function Get-Service($Name, $ErrorAction) {
            if ($Name -eq 'SLIAgentNet') {
                @{ Status = $(if ($script:running) { 'Running' } else { 'Stopped' }) }
            }
        }
        function Stop-Service($InputObject) { $script:running = $false }
        function Start-Service($Name) {
            if ($Name -ne 'SLIAgentNet') { throw 'Unexpected service start.' }
            if ([IO.File]::ReadAllText($identity) -ne 'previous identity' -or
                [IO.File]::ReadAllText($cursor) -ne 'previous cursor') { throw 'Service restarted before restoring state.' }
            $script:running = $true
        }
        function Remove-InstalledAgentMsi($Product) { throw 'The installed .NET MSI must not be explicitly removed.' }
        function Install-AgentMsi($Arguments) {
            if ($script:running) { throw 'Service was not stopped for the snapshot.' }
            if ($Arguments -ne ('/i "{0}" /qn /norestart' -f $msi)) { throw 'Upgrade must keep the installed bootstrap settings.' }
            $archive = Join-Path $work 'previous-state'
            if ([IO.File]::ReadAllText((Join-Path $archive 'identity.json')) -ne 'previous identity' -or
                [IO.File]::ReadAllText((Join-Path (Join-Path $archive 'queue') 'cursor.json')) -ne 'previous cursor' -or
                [IO.File]::ReadAllText($identity) -ne 'previous identity') { throw 'Upgrade did not preserve the original state.' }
            $script:invoked = $true
            if ($Outcome -eq 'failure') {
                [IO.File]::WriteAllText($identity, 'changed identity')
                [IO.File]::Delete($cursor)
                # Windows Installer may already have started the old service during rollback.
                $script:running = $true
                throw 'SLI Agent installation failed (1603).'
            }
        }

        try {
            if (!(Update-InstalledAgent @(@{ Service = 'SLIAgentNet' }) $msi $state $work)) { throw 'Expected an MSI update.' }
            if ($Outcome -eq 'failure') { throw 'Expected the installer failure to be reported.' }
        } catch {
            if ($Outcome -ne 'failure' -or $_.Exception.Message -ne 'SLI Agent installation failed (1603).') { throw }
        }
        if (!$script:invoked -or !$script:running) { throw 'The previous agent service is not running after the MSI attempt.' }
        if (Get-ChildItem -LiteralPath $work -Force) { throw 'Temporary rollback data was not cleared.' }
        """;
}
