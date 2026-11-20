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

function Get-PrivateDirectoryPermissionError($Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Unsafe SLI data directory.'
    }
    $acl = Get-Acl -LiteralPath $Path
    $trusted = 'S-1-5-18', 'S-1-5-32-544'
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        return 'Unsafe SLI data directory owner.'
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and
            ($rule.FileSystemRights -band 0xD0156)) {
            return 'Unsafe SLI data directory permissions.'
        }
    }
}

function Assert-PrivateDirectory($Path) {
    $violation = Get-PrivateDirectoryPermissionError $Path
    if ($violation) { throw $violation }
}

function Initialize-SliRoot($Path) {
    if (Test-Path -LiteralPath $Path) {
        $violation = Get-PrivateDirectoryPermissionError $Path
        if (!$violation) { return }
        # Treat any AgentNet entry as current state. Inspect the name without traversing it.
        if (Get-ChildItem -LiteralPath $Path -Force -Filter 'AgentNet') { throw $violation }
        $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmssfffffffZ', [Globalization.CultureInfo]::InvariantCulture)
        [IO.Directory]::Move($Path, "$Path.old-$stamp")
    }
    New-PrivateDirectory $Path
    Assert-PrivateDirectory $Path
}

function Get-InstalledAgentProducts {
    # Query registered MSI families without touching Win32_Product or triggering repairs.
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try {
        foreach ($family in @(
            @{ Code = '{D6836D37-49FA-4AB6-BDFD-10B07ED51973}'; Service = 'SLIAgent' },
            @{ Code = '{BE66EC86-AE25-4D3F-8C60-B191F3B0E20D}'; Service = 'SLIAgentNet' }
        )) {
            foreach ($value in @($installer.RelatedProducts($family.Code))) {
                $code = [guid]::ParseExact($value, 'B')
                if ($code -eq [guid]::Empty) { throw 'Invalid SLI Agent MSI product code.' }
                @{ Code = $code.ToString('B'); Service = $family.Service }
            }
        }
    } finally {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    }
}

function Test-LegacyAgentServiceMissing {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\SLIAgent'
    if (!(Test-Path -LiteralPath $key)) { return $true }
    $serviceKey = Get-Item -LiteralPath $key
    try { $account = $serviceKey.GetValue('ObjectName') }
    finally { $serviceKey.Dispose() }
    if (!$account) { return $true }
    if ($account -in 'LocalSystem', 'NT AUTHORITY\SYSTEM') { return $false }
    if ($account.StartsWith('.\')) { $account = $env:COMPUTERNAME + $account.Substring(1) }
    try {
        [void][Security.Principal.NTAccount]::new($account).Translate([Security.Principal.SecurityIdentifier])
        return $false
    } catch [Security.Principal.IdentityNotMappedException] {
        return $true
    }
}

function Remove-InstalledAgentMsi($Product) {
    $arguments = '/x {0} /qn /norestart' -f $Product.Code
    $legacyMissing = $Product.Service -eq 'SLIAgent' -and (Test-LegacyAgentServiceMissing)
    $process = Start-Process -FilePath (Join-Path ([Environment]::SystemDirectory) 'msiexec.exe') `
        -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    if ($legacyMissing -and $process.ExitCode -eq 1603) {
        # Released Python MSIs run their cached custom action. Keep their local
        # state and rollback records when that action fails without its service.
        $process = Start-Process -FilePath (Join-Path ([Environment]::SystemDirectory) 'msiexec.exe') `
            -ArgumentList ($arguments + ' PRESERVE_STATE=1') -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -in 0, 3010) { Write-Host 'Previous SLI Agent state was retained.' }
    }
    if ($process.ExitCode -notin 0, 1605, 3010) { throw "SLI Agent removal failed ($($process.ExitCode))." }
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
$state = Join-Path $data 'state'
$registration = 'SOFTWARE\SLI\AgentNet'
# A custom state directory can be under SLI without an AgentNet entry.
$current = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($registration)
if ($current) {
    try {
        $configuredState = $current.GetValue('StateDirectory')
        if ($configuredState -and $configuredState -ne $state) { throw 'SLI Agent has a custom state directory.' }
    } finally { $current.Dispose() }
}
Initialize-SliRoot $sliRoot
if (!(Test-Path -LiteralPath $data)) { New-PrivateDirectory $data }
Assert-PrivateDirectory $data
# The .NET uninstaller cleans its own data directory, including its install lock
# and old downloads. Keep the new verified MSI and the lock outside that tree.
$work = Join-Path $sliRoot ('install-agent-' + [guid]::NewGuid().ToString('N'))
New-PrivateDirectory $work
$msi = Join-Path $work 'SliAgent.msi'
$id = [guid]::NewGuid().ToString('N')
$backup = Join-Path $data ('previous-' + $id)
$caPath = Join-Path $data ('ca-' + $id + '.crt')
$keyPath = Join-Path $state ('enroll-' + $id + '.txt')
$settings = 'ServerUrl', 'CaBundle', 'CaFingerprint', 'TokenFile', 'InstanceName', 'EnrollmentToken'
$registry = $null
$prior = @{}
$changed = $false
$archived = $false
$newState = $false
$committed = $false
$lock = $null
try {
    $lock = [IO.File]::Open((Join-Path $sliRoot 'install-agent.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
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

    $products = @(Get-InstalledAgentProducts)
    if (Test-Path -LiteralPath $state) { Assert-PrivateDirectory $state }
    if (Test-Path -LiteralPath (Join-Path $data 'agent.json')) { throw 'SLI Agent has custom machine settings.' }
    foreach ($product in $products) {
        Write-Host 'Removing previous SLI Agent...'
        Remove-InstalledAgentMsi $product
    }
    if (Get-Service -Name 'SLIAgent', 'SLIAgentNet' -ErrorAction SilentlyContinue) {
        throw 'An SLI Agent service remains after MSI removal.'
    }
    if (!(Test-Path -LiteralPath $data)) { New-PrivateDirectory $data }
    Assert-PrivateDirectory $data
    $registry = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($registration, $true)
    if ($registry) {
        foreach ($name in $settings) {
            $value = $registry.GetValue($name)
            if ($null -ne $value) { $prior[$name] = $value }
        }
    }
    if (Test-Path -LiteralPath $state) { Assert-PrivateDirectory $state }

    Write-Host 'Configuring SLI Agent...'
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
    $arguments = '/i "{0}" /qn /norestart SERVER_URL="{1}" CA_FILE="{2}" TOKEN_FILE="{3}"' -f $msi, $Server, $caPath, $keyPath
    $process = Start-Process -FilePath (Join-Path ([Environment]::SystemDirectory) 'msiexec.exe') -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -notin 0, 3010) { throw "SLI Agent installation failed ($($process.ExitCode))." }
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
    }
    if ($registry) { $registry.Dispose() }
    if ($lock) { $lock.Dispose() }
    if ([IO.File]::Exists($msi)) { [IO.File]::Delete($msi) }
    [IO.Directory]::Delete($work)
}
