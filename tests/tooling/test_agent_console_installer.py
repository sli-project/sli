import base64
import hashlib
import json
import os
import shutil
import ssl
import subprocess
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import IPv4Address
from pathlib import Path
from threading import Thread

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


INSTALLER = Path(__file__).resolve().parents[2] / 'server-dotnet/src/Sli.Server/Agents/Control/InstallAgent.ps1'
INITIALIZE = r'''
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$null, [ref]$null)
$initializer = $ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
     $node.Name -eq 'Initialize-SliAgentPinnedPackage'}, $true)
. ([scriptblock]::Create($initializer.Extent.Text))
Initialize-SliAgentPinnedPackage
'''


@pytest.mark.parametrize('shell', ['pwsh', 'powershell'])
def test_old_msi_removal_retries_only_for_missing_legacy_service(tmp_path, shell):
    executable = shutil.which(shell)
    if executable is None:
        pytest.skip(f'{shell} is unavailable')
    harness = tmp_path / 'uninstall.ps1'
    harness.write_text(r'''
param($Installer)
$ErrorActionPreference = 'Stop'
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$null, [ref]$errors)
if ($errors) { throw ($errors | Out-String) }
$remove = $ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Remove-InstalledAgentMsi'}, $true)
. ([scriptblock]::Create($remove.Extent.Text))
function Test-LegacyAgentServiceMissing { return $script:missing }
# On Linux the shell has no Windows system directory. Resolve the fake
# executable name without calling the Windows-only installer.
if (![Environment]::SystemDirectory) {
    function Join-Path($Path, $ChildPath) { [IO.Path]::Combine($Path, $ChildPath) }
}
function Start-Process {
    param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru, $WindowStyle)
    if ([IO.Path]::GetFileName($FilePath) -ne 'msiexec.exe') { throw 'Unexpected installer executable.' }
    $script:calls.Add($ArgumentList)
    return @{ ExitCode = $script:codes.Dequeue() }
}
$product = @{ Code = '{00000000-0000-4000-8000-000000000001}'; Service = 'SLIAgent' }
function RunCase($Service, $Missing, [int[]]$Codes) {
    $product.Service = $Service
    $script:missing = $Missing
    $script:codes = [Collections.Generic.Queue[int]]::new()
    foreach ($code in $Codes) { $script:codes.Enqueue($code) }
    $script:calls = [Collections.Generic.List[string]]::new()
    try { Remove-InstalledAgentMsi $product; 'removed' } catch { $_.Exception.Message }
    $script:calls
}
RunCase SLIAgent $true @(1603, 0)
RunCase SLIAgent $false @(1603)
RunCase SLIAgentNet $true @(1603)
RunCase SLIAgentNet $false @(0)
''', encoding='ascii')
    result = subprocess.run([executable, '-NoProfile', '-File', str(harness), str(INSTALLER)],
                            capture_output=True, text=True, timeout=45, check=True)
    remove = '/x {00000000-0000-4000-8000-000000000001} /qn /norestart'
    assert result.stdout.splitlines() == [
        'Previous SLI Agent state was retained.', 'removed', remove, f'{remove} PRESERVE_STATE=1',
        'SLI Agent removal failed (1603).', remove,
        'SLI Agent removal failed (1603).', remove, 'removed', remove,
    ]


@pytest.mark.parametrize('shell', ['pwsh', 'powershell'])
def test_installer_archives_unsafe_legacy_directory_without_moving_dotnet_state(tmp_path, shell):
    executable = shutil.which(shell)
    if executable is None:
        pytest.skip(f'{shell} is unavailable')
    for case in ('legacy', 'dotnet', 'private', 'file'):
        (tmp_path / case).mkdir()
    legacy = tmp_path / 'legacy' / 'SLI'
    legacy.mkdir()
    (legacy / 'legacy.txt').write_text('previous state', encoding='ascii')
    dotnet = tmp_path / 'dotnet' / 'SLI' / 'AgentNet' / 'state'
    dotnet.mkdir(parents=True)
    (dotnet / 'current.txt').write_text('current state', encoding='ascii')
    private = tmp_path / 'private' / 'SLI'
    private.mkdir()
    (private / 'keep.txt').touch()
    (tmp_path / 'file' / 'SLI').touch()
    harness = tmp_path / 'data-directory.ps1'
    harness.write_text(r'''
param($Installer)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$null, [ref]$errors)
if ($errors) { throw ($errors | Out-String) }
foreach ($definition in $ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @(
        'Get-PrivateDirectoryPermissionError', 'Assert-PrivateDirectory', 'Initialize-SliRoot')
}, $false)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
# Simulate Windows ACLs on both CI platforms while using the real filesystem for the rename.
$privatePaths = @{ (Join-Path $PSScriptRoot 'private/SLI') = $true }
function New-PrivateDirectory($Path) {
    [IO.Directory]::CreateDirectory($Path) | Out-Null
    $privatePaths[$Path] = $true
}
function Get-Acl($LiteralPath) {
    $acl = [pscustomobject]@{ Private = $privatePaths.ContainsKey($LiteralPath) }
    $acl | Add-Member ScriptMethod GetOwner { @{ Value = 'S-1-5-32-544' } }
    $acl | Add-Member ScriptMethod GetAccessRules {
        if (!$this.Private) {
            @{ AccessControlType = 'Allow'; IdentityReference = @{ Value = 'S-1-5-32-545' }; FileSystemRights = 2 }
        }
    }
    return $acl
}
Initialize-SliRoot (Join-Path $PSScriptRoot 'legacy/SLI')
Initialize-SliRoot (Join-Path $PSScriptRoot 'private/SLI')
foreach ($case in 'dotnet', 'file') {
    try { Initialize-SliRoot (Join-Path $PSScriptRoot "$case/SLI"); 'unexpected success' }
    catch { $_.Exception.Message }
}
''', encoding='ascii')
    result = subprocess.run([executable, '-NoProfile', '-File', str(harness), str(INSTALLER)],
                            capture_output=True, text=True, timeout=45, check=True)
    assert result.stdout.splitlines() == ['Unsafe SLI data directory permissions.', 'Unsafe SLI data directory.']
    archive, = legacy.parent.glob('SLI.old-*')
    assert (archive / 'legacy.txt').read_text(encoding='ascii') == 'previous state'
    assert legacy.is_dir() and not list(legacy.iterdir())
    assert (dotnet / 'current.txt').read_text(encoding='ascii') == 'current state'
    assert (private / 'keep.txt').is_file()
    for case in ('dotnet', 'private', 'file'):
        assert not list((tmp_path / case).glob('SLI.old-*'))


def certificate(name, issuer=None, issuer_key=None, *, expired=False):
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer.subject if issuer else subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(hours=-1 if expired else 24))
               .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=None), critical=True))
    if issuer:
        builder = (builder.add_extension(x509.SubjectAlternativeName([x509.IPAddress(IPv4Address('127.0.0.1'))]), False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False))
    return builder.sign(issuer_key or key, hashes.SHA256()), key


@pytest.mark.parametrize('shell', ['pwsh', 'powershell'])
def test_installer_checks_exact_ca_expiration_and_server_name(shell, tmp_path):
    executable = shutil.which(shell)
    if executable is None:
        pytest.skip(f'{shell} is unavailable')
    root, root_key = certificate('root.example.test')
    other_root, _ = certificate('other-root.example.test')
    leaf, _ = certificate('sli.example.test', root, root_key)
    expired, _ = certificate('sli.example.test', root, root_key, expired=True)
    for name, cert in [('root', root), ('other-root', other_root), ('leaf', leaf), ('expired', expired)]:
        (tmp_path / f'{name}.der').write_bytes(cert.public_bytes(serialization.Encoding.DER))
    harness = tmp_path / 'chain.ps1'
    harness.write_text('param($Installer)\n' + INITIALIZE + r'''
function Read-FixtureCert($Name) {
    return [Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $PSScriptRoot "$Name.der"))
}
$root = Read-FixtureCert 'root'
$other = Read-FixtureCert 'other-root'
$leaf = Read-FixtureCert 'leaf'
$expired = Read-FixtureCert 'expired'
$untrusted = [Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors
[SliAgentPinnedPackage]::IsPinnedServerCertificate($leaf, $null, $untrusted, $root)
[SliAgentPinnedPackage]::IsPinnedServerCertificate($leaf, $null, $untrusted, $other)
[SliAgentPinnedPackage]::IsPinnedServerCertificate($expired, $null, $untrusted, $root)
[SliAgentPinnedPackage]::IsPinnedServerCertificate($leaf, $null, [Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch, $root)
''', encoding='ascii')
    result = subprocess.run([executable, '-NoProfile', '-File', str(harness), str(INSTALLER)],
                            capture_output=True, text=True, timeout=45, check=True)
    assert result.stdout.splitlines() == ['True', 'False', 'False', 'False']


@pytest.mark.parametrize('shell', ['pwsh', 'powershell'])
def test_installer_checks_pinned_tls_and_package_bytes(tmp_path, shell):
    executable = shutil.which(shell)
    if executable is None:
        pytest.skip(f'{shell} is unavailable')
    root, root_key = certificate('root.example.test')
    other_root, _ = certificate('other-root.example.test')
    leaf, leaf_key = certificate('sli.example.test', root, root_key)
    cert_path, key_path = tmp_path / 'tls.crt', tmp_path / 'tls-key.pem'
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    package = b'synthetic agent package'
    digest = hashlib.sha256(package).hexdigest()
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', '/ok')
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('X-SLI-Package-SHA256', '0' * 64 if self.path == '/wrong-digest' else digest)
            self.end_headers()
            self.wfile.write(b'changed payload' if self.path == '/wrong-body' else package)

        def log_message(self, *_args):
            pass

    def pinned(cert):
        der = cert.public_bytes(serialization.Encoding.DER)
        return base64.b64encode(der).decode('ascii'), hashlib.sha256(der).hexdigest()

    with HTTPServer(('127.0.0.1', 0), Handler) as server:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert_path, key_path)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        host, port = server.server_address
        url = f'https://{host}:{port}'
        der, pin = pinned(root)
        cases = {
            'ok': [f'{url}/ok', der, pin],
            'wrong-pin': [f'{url}/ok', der, '0' * 64],
            'wrong-root': [f'{url}/ok', *pinned(other_root)],
            'wrong-host': [f'https://localhost:{port}/ok', der, pin],
            'redirect': [f'{url}/redirect', der, pin],
            'http': [f'http://{host}:{port}/ok', der, pin],
            'wrong-digest': [f'{url}/wrong-digest', der, pin],
            'wrong-body': [f'{url}/wrong-body', der, pin],
        }
        settings = tmp_path / 'cases.json'
        settings.write_text(json.dumps(cases), encoding='ascii')
        harness = tmp_path / 'download.ps1'
        harness.write_text('param($Installer, $Settings, $Digest)\n' + INITIALIZE + r'''
$cases = Get-Content -LiteralPath $Settings -Raw | ConvertFrom-Json
foreach ($case in $cases.PSObject.Properties) {
    $url, $der, $pin = $case.Value
    try {
        [SliAgentPinnedPackage]::Download($url, (Join-Path $PSScriptRoot "$($case.Name).msi"),
            [Convert]::FromBase64String($der), $pin, $Digest)
        "$($case.Name)=ok"
    } catch {
        "$($case.Name)=$($_.Exception.GetBaseException().Message)"
    }
}
''', encoding='ascii')
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = subprocess.run([executable, '-NoProfile', '-File', str(harness), str(INSTALLER), str(settings), digest],
                                    env={**os.environ, 'HTTPS_PROXY': 'http://127.0.0.1:1', 'NO_PROXY': ''},
                                    capture_output=True, text=True, timeout=45, check=True)
        finally:
            server.shutdown()
            thread.join()

    results = dict(line.split('=', 1) for line in result.stdout.splitlines())
    assert results.keys() == cases.keys()
    assert [case for case, outcome in results.items() if outcome == 'ok'] == ['ok'], results
    assert 'fingerprint mismatch' in results['wrong-pin']
    assert 'hash differs' in results['wrong-digest']
    assert 'hash verification failed' in results['wrong-body']
    assert hits == ['/ok', '/redirect', '/wrong-digest', '/wrong-body']
    assert (tmp_path / 'ok.msi').read_bytes() == package
