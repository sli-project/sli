param($Server, $RegistrationKey, $CaDer, $CaPin, $PackageSha256)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function New-PrivateDirectory($Path) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
    } else {
        [IO.FileSystemAclExtensions]::CreateDirectory($acl, $Path) | Out-Null
    }
}

function Assert-PrivateDirectory($Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Unsafe SLI data directory.'
    }
    $acl = Get-Acl -LiteralPath $Path
    $trusted = 'S-1-5-18', 'S-1-5-32-544'
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw 'Unsafe SLI data directory owner.'
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and
            ($rule.FileSystemRights -band 0xD0156)) {
            throw 'Unsafe SLI data directory permissions.'
        }
    }
}

function Get-AgentPackageVersion($Path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Path, 0)
    $view = $database.OpenView('SELECT `Value` FROM `Property` WHERE `Property` = ''ProductVersion''')
    try {
        $view.Execute() | Out-Null
        return [version]$view.Fetch().StringData(1)
    } finally {
        $view.Close() | Out-Null
    }
}

function Move-PreviousAgentState($State, $Archive) {
    if (!(Test-Path -LiteralPath $State)) { return $false }
    [IO.Directory]::Move($State, $Archive)
    return $true
}

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or ![Environment]::Is64BitProcess) {
    throw 'Open 64-bit PowerShell as Administrator.'
}

function Initialize-SliAgentPinnedPackage {
    if ('SliAgentPinnedPackage' -as [type]) { return }
    # A compiled delegate can run on the TLS thread in Windows PowerShell 5.1.
    $downloadSource = @'
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public static class SliAgentPinnedPackage {
    public static bool IsPinnedServerCertificate(X509Certificate leaf, X509Chain presented, SslPolicyErrors errors, X509Certificate2 root) {
        if (leaf == null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None) return false;
        using (var certificate = new X509Certificate2(leaf))
        using (var chain = new X509Chain()) {
            chain.ChainPolicy.ExtraStore.Add(root);
            if (presented != null) foreach (X509ChainElement element in presented.ChainElements)
                chain.ChainPolicy.ExtraStore.Add(element.Certificate);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            var certificateDownloads = typeof(X509ChainPolicy).GetProperty("DisableCertificateDownloads");
            if (certificateDownloads != null) certificateDownloads.SetValue(chain.ChainPolicy, true, null);
            // id-kp-serverAuth
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(String.Join(".", new[] { 1, 3, 6, 1, 5, 5, 7, 3, 1 })));
            if (!chain.Build(certificate) || chain.ChainElements.Count < 2) return false;
            foreach (var status in chain.ChainStatus)
                if ((status.Status & ~X509ChainStatusFlags.UntrustedRoot) != 0) return false;
            return String.Equals(chain.ChainElements[chain.ChainElements.Count - 1].Certificate.GetRawCertDataString(),
                root.GetRawCertDataString(), StringComparison.Ordinal);
        }
    }

    public static void Download(string source, string destination, byte[] ca, string pin, string packageSha256) {
        Uri uri;
        if (!Uri.TryCreate(source, UriKind.Absolute, out uri) || uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length != 0)
            throw new InvalidOperationException("SLI installer requires an HTTPS server URL.");
        using (var root = new X509Certificate2(ca))
        using (var sha = SHA256.Create()) {
            if (!String.Equals(BitConverter.ToString(sha.ComputeHash(ca)).Replace("-", ""), pin,
                StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("SLI CA fingerprint mismatch.");
            var request = (HttpWebRequest)WebRequest.Create(uri);
            request.AllowAutoRedirect = false;
            request.KeepAlive = false;
            request.Proxy = null;
            request.Timeout = System.Threading.Timeout.Infinite;
            request.ReadWriteTimeout = System.Threading.Timeout.Infinite;
            request.ServerCertificateValidationCallback = delegate(object sender, X509Certificate leaf, X509Chain presented, SslPolicyErrors errors) {
                return IsPinnedServerCertificate(leaf, presented, errors, root);
            };
            using (var response = (HttpWebResponse)request.GetResponse()) {
                if (response.StatusCode != HttpStatusCode.OK) throw new InvalidOperationException("SLI installer download failed.");
                if (!String.Equals(response.Headers["X-SLI-Package-SHA256"], packageSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("SLI installer hash differs from the installation command. Create a new command.");
                using (var input = response.GetResponseStream())
                using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)) {
                    input.CopyTo(output);
                    output.Position = 0;
                    var actual = BitConverter.ToString(sha.ComputeHash(output)).Replace("-", "");
                    if (!String.Equals(actual, packageSha256, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("SLI installer hash verification failed.");
                }
            }
        }
    }
}
'@
    $compiler = @{}
    if ($PSVersionTable.PSEdition -eq 'Core') { $compiler.CompilerOptions = '/nowarn:SYSLIB0014,SYSLIB0057' }
    Add-Type -TypeDefinition $downloadSource @compiler
}
Initialize-SliAgentPinnedPackage

$programData = [Environment]::GetFolderPath('CommonApplicationData')
$sliRoot = Join-Path $programData 'SLI'
$data = Join-Path $sliRoot 'AgentNet'
foreach ($directory in @($sliRoot, $data)) {
    if (!(Test-Path -LiteralPath $directory)) { New-PrivateDirectory $directory }
    Assert-PrivateDirectory $directory
}
$work = Join-Path $data ('install-' + [guid]::NewGuid().ToString('N'))
New-PrivateDirectory $work
$msi = Join-Path $work 'SliAgent.msi'
$state = Join-Path $data 'state'
$id = [guid]::NewGuid().ToString('N')
$backup = Join-Path $data ('previous-' + $id)
$caPath = Join-Path $data ('ca-' + $id + '.crt')
$keyPath = Join-Path $state ('enroll-' + $id + '.txt')
$registration = 'SOFTWARE\SLI\AgentNet'
$settings = 'ServerUrl', 'CaBundle', 'CaFingerprint', 'TokenFile', 'InstanceName', 'EnrollmentToken'
$registry = $null
$prior = @{}
$changed = $false
$stopped = $false
$archived = $false
$newState = $false
$committed = $false
$lock = $null
try {
    $lock = [IO.File]::Open((Join-Path $data 'install.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    Write-Host 'Downloading SLI Agent...'
    $ca = [Convert]::FromBase64String($CaDer)
    try {
        [SliAgentPinnedPackage]::Download(($Server + 'api/v1/agent/installer/SliAgent.msi'), $msi, $ca, $CaPin, $PackageSha256)
    } catch {
        $failure = $_.Exception.GetBaseException()
        if ($failure -is [Net.WebException] -and $failure.Response -is [Net.HttpWebResponse] -and
            $failure.Response.StatusCode -eq [Net.HttpStatusCode]::NotFound) {
            throw 'The SLI server has no agent installation package.'
        }
        throw
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $msi
    if ($signature.Status -ne 'Valid' -and ($signature.Status -ne 'NotSigned' -or $signature.SignerCertificate)) {
        throw 'SLI installer Authenticode signature is invalid.'
    }

    $service = Get-Service -Name 'SLIAgentNet' -ErrorAction SilentlyContinue
    $registry = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($registration, $true)
    if ($registry) {
        foreach ($name in $settings) {
            $value = $registry.GetValue($name)
            if ($null -ne $value) { $prior[$name] = $value }
        }
        $configuredState = $registry.GetValue('StateDirectory')
        if ($configuredState -and $configuredState -ne $state) { throw 'SLI Agent has a custom state directory.' }
    }
    if (Test-Path -LiteralPath (Join-Path $data 'agent.json')) { throw 'SLI Agent has custom machine settings.' }
    if ($service -and !$registry) { throw 'SLI Agent installation settings are missing.' }
    $install = !$service
    if ($service) {
        $installed = $registry.OpenSubKey('Product')
        if (!$installed) { throw 'SLI Agent MSI product information is missing.' }
        try { $install = (Get-AgentPackageVersion $msi) -gt [version]$installed.GetValue('Version') }
        finally { $installed.Dispose() }
    }
    if (Test-Path -LiteralPath $state) { Assert-PrivateDirectory $state }
    if ($service -and $prior['ServerUrl'] -and $prior['ServerUrl'].TrimEnd('/') -eq $Server.TrimEnd('/') -and
        (Test-Path -LiteralPath (Join-Path $state 'identity.json')) -and $prior['CaBundle'] -and
        [IO.File]::Exists($prior['CaBundle'])) {
        $savedCa = [IO.File]::ReadAllText($prior['CaBundle']) -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', ''
        if ($savedCa -ceq $CaDer) {
            if ($install) {
                $upgrade = Start-Process -FilePath (Join-Path ([Environment]::SystemDirectory) 'msiexec.exe') `
                    -ArgumentList ('/i "{0}" /qn /norestart' -f $msi) -Wait -PassThru -WindowStyle Hidden
                if ($upgrade.ExitCode -notin 0, 3010) { throw "SLI Agent upgrade failed ($($upgrade.ExitCode))." }
            }
            Start-Service -Name 'SLIAgentNet'
            Write-Host 'SLI Agent is already connected to this server.'
            return
        }
    }

    Write-Host 'Configuring SLI Agent...'
    if ($service -and $service.Status -ne 'Stopped') {
        Stop-Service -Name 'SLIAgentNet'
        $stopped = $true
    }
    $archived = Move-PreviousAgentState $state $backup
    New-PrivateDirectory $state
    $newState = $true
    $pem = "-----BEGIN CERTIFICATE-----`r`n" +
        [Convert]::ToBase64String($ca, [Base64FormattingOptions]::InsertLineBreaks) +
        "`r`n-----END CERTIFICATE-----`r`n"
    [IO.File]::WriteAllText($caPath, $pem)
    [IO.File]::WriteAllText($keyPath, $RegistrationKey)

    if ($registry) {
        $changed = $true
        $registry.SetValue('ServerUrl', $Server)
        $registry.SetValue('CaBundle', $caPath)
        $registry.SetValue('TokenFile', $keyPath)
        foreach ($name in @('CaFingerprint', 'InstanceName', 'EnrollmentToken')) { $registry.DeleteValue($name, $false) }
    }
    if ($install) {
        $arguments = '/i "{0}" /qn /norestart SERVER_URL="{1}" CA_FILE="{2}" TOKEN_FILE="{3}"' -f $msi, $Server, $caPath, $keyPath
        $process = Start-Process -FilePath (Join-Path ([Environment]::SystemDirectory) 'msiexec.exe') -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -notin 0, 3010) { throw "SLI Agent installation failed ($($process.ExitCode))." }
    } else {
        Start-Service -Name 'SLIAgentNet'
    }
    $committed = $true
    Write-Host 'SLI Agent service started. Check the Agents page for its last connection.'
} finally {
    if (!$committed) {
        if ($newState -and (Test-Path -LiteralPath $keyPath)) { [IO.File]::Delete($keyPath) }
        if ($changed) {
            foreach ($name in $settings) {
                if ($prior.ContainsKey($name)) { $registry.SetValue($name, $prior[$name]) }
                else { $registry.DeleteValue($name, $false) }
            }
        }
        if ($newState) { [IO.Directory]::Delete($state, $true) }
        if ($archived) { [IO.Directory]::Move($backup, $state) }
        if ([IO.File]::Exists($caPath)) { [IO.File]::Delete($caPath) }
        if ($stopped) { Start-Service -Name 'SLIAgentNet' }
    }
    if ($registry) { $registry.Dispose() }
    if ($lock) { $lock.Dispose() }
    if ([IO.File]::Exists($msi)) { [IO.File]::Delete($msi) }
    [IO.Directory]::Delete($work)
}
