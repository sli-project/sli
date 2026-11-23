# Windows agent installation

[Русская версия](AGENT_INSTALL.ru.md) · [Server installation](SERVER_INSTALL.en.md)

These procedures describe the older Python agent and Docker evaluation workflow. For the .NET agent shipped with the native Debian beta, use [Connect a Windows agent](../en/windows-agent.md).

The Apache-2.0 Python agent makes outbound HTTPS connections from monitored
Windows hosts, including DCs and workstations. It has no database credentials
or Docker access. Start with heartbeat only; collection requires separate
authorization. See the [enrollment guide](../agent-enrollment.md).

## Demo lab: agent on a Windows Server 2019 DC

Run the [orchestrator](../../tools/lab/lab-orchestrate.ps1) in elevated Windows
PowerShell 5.1 on the owner's PC with OpenSSH and Docker CLI. It needs a separate
clean Windows Server 2019 VDS (build 17763), working administrator SSH/key access
using `~/.ssh/id_ed25519_demo`, a trusted MSI/build SHA-256 sidecar and the current
SLI public CA. SSH uses `accept-new` on first contact and checks the saved host
key thereafter. Input variables contain a target and paths, not passwords/tokens:

```powershell
$vds = $env:SLI_LAB_SSH_TARGET
$msi = $env:SLI_LAB_MSI_PATH
$ca = $env:SLI_LAB_CA_PATH
$sha = (Get-Content -LiteralPath ($msi + '.sha256') -Raw).Trim().Split(' ')[0]
.\tools\lab\lab-orchestrate.ps1 -Target $vds -MsiPath $msi -CaFile $ca -MsiSha256 $sha
```

Scripts create `LAB-DC01`, the `demo.example` / `DEMO` forest and DNS, eight
department OUs under Departments, server/workstation/service OUs, 150 fictional
Russian users (three disabled), two service accounts with SPNs, 40 computer
objects, VPN/department groups and nested membership including Backup Operators.
Eight GPOs have links/settings; password policy uses `GptTmpl.inf` plus AD,
and advanced auditing uses `audit.csv` with its CSE
([Microsoft format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/eda6a094-5d0a-4516-a3ab-7ee2d38b12b6)).
Lab GPC SACLs permit 5136 observation. Computer objects are inventory, not
running/joined OSes. NPS/VPN servers and workstation OSes are not provisioned.

A SYSTEM task resumes after renaming/promoting the DC across up to two reboots.
The orchestrator waits up to 30 minutes for readiness, then starts a hidden
reconnecting SSH supervisor with `-R 127.0.0.1:8443:localhost:8443`.
SLI remains private; keep the owner's PC awake. The SLI certificate must include
a `localhost` SAN; TLS/CA validation remains enabled. The supervisor PID is
printed. Stop it and its child `ssh.exe` to close the tunnel. Repeated launches
for the same target do not create another active tunnel.

Orchestrator command sequence for the caller's PR description (SSH uses
`powershell.exe -EncodedCommand`; scp uses the key and `BatchMode=yes`):

1. SSH: create `C:\SLI-Lab` and `bootstrap` with SYSTEM/Administrators DACLs **before** scp.
2. SCP: `lab-common.ps1`, `lab-01-domain.ps1`, `lab-02-populate.ps1`,
   `lab-03-simulate.ps1`, `lab-04-agent.ps1`, `lab-data.json` to `C:/SLI-Lab/`.
3. SSH: `& C:\SLI-Lab\lab-01-domain.ps1`; wait for `domain-ready` after reboots.
4. Locally: `lab-tunnel.ps1 -Target $vds`; SCP MSI/CA to `C:/SLI-Lab/bootstrap/`.
5. SSH: `& C:\SLI-Lab\lab-04-agent.ps1 -Phase Prepare -MsiSha256 $sha`;
   SCP `bootstrap/prepare.json` back (public UUID/fingerprint only).
6. On the PC, `Invoke-LabProcess` privately captures stdout from
   `docker exec sli-api-1 python -m server.sli.agents.issue_token --host-id <UUID>
   --key-fingerprint <SHA256> --ttl 900 --actor sli-lab-orchestrator`.
   Never issue a token with stdout going directly to the terminal.
7. `Write-LabSecret` creates a protected local file; SCP transfers
   `enrollment.token` to protected VDS bootstrap; `finally` removes the PC copy.
8. SSH: `& C:\SLI-Lab\lab-04-agent.ps1 -Phase Enroll`: staged-token removal,
   service startup, waiting for identity and fresh status without delivery errors.

Reruns reuse owned objects, membership, GPOs, DSRM/user passwords and agent
identity. Existing user passwords are never reset. Missing password files and
foreign name collisions fail closed. An enrolled agent gets no new token.
Secrets remain on the VDS under `C:\SLI-Lab`/the protected agent directory;
do not enable transcripts. Regenerate the manifest on a development machine
with `python tools/lab/lab_model.py --output tools/lab/lab-data.json`; the VDS
needs no system Python. PowerShell files use UTF-8 with BOM.

`SLI Lab Day` runs every five minutes, weekdays 09:00–18:00 in the VDS timezone,
with rare night logons. LDAP Negotiate binds to `127.0.0.1:389` generate successes,
wrong passwords, daily spraying across 30 accounts, repeated failures for one
account, disabled-account logon, Domain Admins membership addition, GPO change
and audit-policy change (4719). Daily markers/mutex prevent completed-scenario
replay and overlap. Membership/GPO changes remain for subsequent snapshots.
Run today's pending scenarios immediately:

```powershell
. .\tools\lab\lab-common.ps1
$key = Join-Path $env:USERPROFILE '.ssh\id_ed25519_demo'
Invoke-LabRemote $vds $key '& C:\SLI-Lab\lab-03-simulate.ps1 -RunDaily'
```

`expected\<UTC-date>.jsonl` records attempt UUID, scenario, UTC interval, synthetic
target, event IDs, IP, change GUID/SID and `executed`. It records actions, not
proof of Windows/SLI events. The verifier downloads JSONL and uses only GET on
`events.journal`, exact-event API, `security.problems` including evidence,
`ad.infrastructure` and `ad.gpo.v2` changes tabs. It checks source/time/IP/identity
and consumes each event once. Use an existing API key with these report grants
and `evidence.exact` in a protected local file; HTTPS CA must be trusted on the PC.
No keys or SLI policies are created.

```powershell
.\tools\lab\lab-verify.ps1 -Target $vds -DomainId $demoDomainId -ApiKeyFile $protectedApiKeyFile
# For an existing copy: -ExpectedDirectory $expectedDirectory instead of -Target.
```

The table separates Event, AD/GPO and Problem with `FOUND`, `MISSING`,
`UNAVAILABLE`, `SCENARIO_FAILED`. Exit `0` means all required matches; `2` means
gaps/unavailable evidence/failed actions; `1` means setup failure. Problem means
a finding with an exact event reference, not acceptance of a specific password
attack classification rule. AD/GPO changes need baseline and later snapshots;
initial import is not a change. Rerun verification after collection delays.

**Acceptance boundary:** the only SLI write is `issue_token`. Current enrollment
registers a new agent with collection disabled. `lab_agent_registered_waiting_for_server_policy`
means enrollment without collection; `lab_agent_registered_collection_active`
means fresh active status, not report readback. Assigning `ad_dc`, `ad_snapshot`,
`gpo_snapshot` and audit policy requires a separate authorized action on SLI.
Automated “registered and sending events” is impossible without that assignment
within this scope. Script execution alone does not close AG-SNAP/AG-AUDIT;
real Windows/SLI checks are required.

Checks: `/opt/venv/bin/python -m pytest tests/unit/test_lab_tools.py` and
`/opt/venv/bin/ruff check --config .github/ruff-ci.toml tools/lab/lab_model.py
tests/unit/test_lab_tools.py` in the dev container; native parser/fakes:
`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
tests/unit/lab_tools_contract.ps1`. Tests use no DB/AD. Stop generation on the VDS
with `Disable-ScheduledTask -TaskName 'SLI Lab Day'`. No automatic domain/VDS
destruction is performed.

## One-command installation on a host with a local server (pilot)

On the Windows host running the local SLI Docker server, from a trusted checkout:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\install-sli-agent-local.ps1
```

The script requests one UAC confirmation when the session is not elevated.
The running `sli-api-1` server must include `server.sli.agents.issue_token`,
have the enrollment migrations applied, and have issuer, HTTPS and public CA
configured. Docker CLI must be accessible to the local administrator. The URL
comes from `SLI_HEALTH_URL` and the public CA from `SLI_TLS_CA_FILE` inside
the API container; the URL hostname must match the certificate.
`-ServerUrl https://example.invalid:8443` overrides the origin;
`-Container` overrides the container name.

The default MSI is `C:\SLI-Build\artifacts\SLI-Agent-1.0.0-x64.msi`,
pinned to SHA-256
`afc08f33a706103be5280dc3daa04b4e3f2c841abc9910bba1a7ea62f5591dd1`.
`-MsiPath` changes only the path, preserving the hash check. After checking the
MSI, the script disables and stops the pilot `SLI Agent` scheduled task,
installs the MSI as LocalSystem, runs `prepare` with its installed Python,
and issues a token through Docker for that host UUID and key fingerprint.
The token and `token_create` audit record commit in one transaction; actor is
the current local administrator and TTL is 900 seconds. Local Docker server
administration is the authorization boundary for this command; it is not
exposed to agents through the enrollment API.

The token is written directly to `C:\ProgramData\SLI\Agent\enrollment.token`
with a protected DACL permitting SYSTEM and Administrators only. Its value
never enters process arguments, MSI properties, logs or console output.
The service restarts, then the script waits up to two minutes for local identity
and an active server registration matching the UUID/fingerprint with a valid,
unrevoked certificate. Success prints `Агент зарегистрирован: <host_id>` and
exits `0`; failure prints the stage/reason and exits `1`, removing any remaining
token file. The pilot scheduled task remains disabled. Re-running for an
enrolled MSI agent verifies registration without issuing another token;
mismatched existing URL/service-account configuration is rejected.

This is a local pilot only. Collection still requires separate owner assignment
of modules/policy; fleet deployment and group tokens are outside this workflow.

## Per-machine MSI (AG-DEP-4 preparation)

The MSI installs one x64 `SLIAgent` service on Windows 10 / Server 2016 or later.
It includes a private CPython embeddable runtime and locked agent dependencies;
it needs neither a system Python nor a virtual environment. Files are installed
under `C:\Program Files\SLI\Agent`; configuration, keys and buffer live under
`C:\ProgramData\SLI\Agent`. The default protected ACL permits SYSTEM and
Administrators only. No database migration or server deployment is performed.

In an elevated administrator session, or a SYSTEM deployment job:

```powershell
msiexec.exe /i "SLI-Agent-1.0.0-x64.msi" /qn /norestart /L*v "agent-install.log" `
  SERVER_URL="https://example.invalid:8443" `
  CA_FILE="C:\ProgramData\SLI-Bootstrap\server-ca.pem"
```

`SERVER_URL` must be an HTTPS origin without credentials, path or query.
`CA_FILE` is a local public PEM CA bundle copied into the protected agent directory.
Alternatively, set `CA_FINGERPRINT` to the CA certificate's 64 lowercase hex
SHA-256 digits (DER certificate hash). The service obtains that exact CA from
the TLS handshake chain, then uses normal certificate and hostname validation
before sending any HTTP request or token. The endpoint must send the pinned
CA in its TLS chain; if it omits the root, use `CA_FILE`. Both properties may
be supplied to verify a local bundle. Local MSI installation remains offline;
fingerprint bootstrap and enrollment occur in the service after installation.

The service starts automatically, prepares its own key/opaque host UUID and
waits without collecting until enrollment succeeds. Existing one-host tokens
are bound to that prepared key: obtain the public UUID/SPKI using the installed
interpreter's `prepare` command under the service identity, then have the owner
issue the token. Deliver a local UTF-8 file containing only that token to
`C:\ProgramData\SLI\Agent\enrollment.token` through a protected management
channel. Protect it with a noninherited DACL for SYSTEM and Administrators and
an owner from those principals. Apply the same protected ACL/owner to its parent
bootstrap directory; UNC paths, reparse points and hard-linked token files are
rejected. Do not include tokens/keys in a golden image.

An already available protected bootstrap file may instead be transferred by
the installer with the **path-only** property:

```powershell
msiexec.exe /i "SLI-Agent-1.0.0-x64.msi" /qn /norestart `
  SERVER_URL="https://example.invalid:8443" `
  CA_FILE="C:\ProgramData\SLI-Bootstrap\server-ca.pem" `
  TOKEN_FILE="C:\ProgramData\SLI-Bootstrap\enrollment.token"
```

The installer checks the source file ACL and deletes it on read, then places
the material in the protected agent directory. The service reads it once and
deletes it **before** its single enrollment attempt, including on invalid
content or server refusal. Protected bootstrap files expire locally after one
hour (the server token TTL remains authoritative); expired files are removed
even while CA bootstrap is unavailable. After a network failure a fresh owner-issued token
must be delivered; the installer never waits for a server response. An unsafe
ACL is rejected before reading; the operator must remove/fix that source file.
Installation rollback/uninstall removes installer-owned bootstrap material.
Never use `TOKEN=`, a token-valued MSI property, MST, environment variable,
process argument or transcript. `MsiHiddenProperties` cannot protect secrets
on the command line in all logging modes. Collection still requires the
existing server enrollment and explicit module/policy assignment; installation
does not change audit policy, group membership or source permissions.

`SERVICE_ACCOUNT` defaults to `LocalSystem`. It can name a locally provisioned
passwordless service identity (for example an administrator-provisioned gMSA).
Provision its Log on as a service and machine authorization separately. No
password property is supported or stored. This explicit choice adds only that
resolved SID to the protected agent ACL alongside SYSTEM and Administrators;
subsequent service-created state retains those principals. Password-based
accounts must be configured through protected local Windows administration.
Repair restores the installed account and preserves configuration, identity
and buffer; install properties do not silently reenroll or replace them.

GPO computer startup scripts, SCCM application jobs and Intune Win32 wrappers
may use the same `/qn /norestart` command in SYSTEM/per-machine context. Stage
the MSI and public CA locally first; deliver bootstrap separately, never embed
a token in policy, MST or an Intune command. Native GPO Software Installation
can use an MST containing only public URL/CA-path properties. Use the MSI
ProductCode for detection/removal. Standard results include success `0`,
restart required `3010` and failure `1603`; inspect the fixed human-readable
SLI Agent error in the MSI log. This PR prepares the installer only and does
not authorize mass deployment.

```powershell
msiexec.exe /x "SLI-Agent-1.0.0-x64.msi" /qn /norestart /L*v "agent-remove.log"
```

Uninstall stops/removes the service and deletes the MSI-owned local keys,
configuration and complete buffer without contacting the server. Resolve unsafe
reparse points if cleanup is rejected; a failed uninstall is not proof of
removal. Revoke the certificate separately in the owner registry: server-side
revocation and draining buffered events are outside this installer. This first
deliverable supports one default instance; it refuses an existing pilot service
or unmanaged state. MSI major upgrades use the workflow below. #444/#536 ZIP
updates cannot replace MSI-owned files: an authenticated `agent_update_msi_required`
result counts towards the server wave's failure threshold. MSI distribution by
server waves is not supported by their current signed ZIP package contract.
Deploy the server with forward migration 195 before using this outcome in waves.

### Upgrade a registered MSI agent

On an elevated Windows PowerShell 5.1 session, stage the new and previous **full**
MSIs and obtain both SHA-256 values from trusted build artifacts. The cached
Windows Installer LocalPackage does not contain the full embedded payload.

```powershell
./tools/install-sli-agent-local.ps1 -Upgrade -MsiPath $newMsi -MsiSha256 $newHash -PreviousMsiPath $oldMsi -PreviousMsiSha256 $oldHash
```

The previous ProductCode/version must match the installed package. The new
ProductCode must differ, its UpgradeCode must match, and its MSI version must
increase. The command requires no Docker, token, enrollment or server access.
It moves the entire protected ProgramData tree to a sibling before removing
the old product inside the MSI transaction. The new MSI restores it before
starting SLIAgent, preserving identity, DPAPI keys, certificates, configuration,
buffer, receipts, cursors and audit rollback records. It observes the service
for 30 seconds. Installation/startup failure restores the previous MSI and the
latest durable state; the command then returns failure with a rollback message.
Both packages and restricted logs remain in `ProgramData/SLI/Agent.upgrade-work-*`.
A failed rollback retains state for recovery and never claims success.
An MSI timeout retains the state and packages without racing a potentially
unfinished Windows Installer transaction; recovery must wait for it to finish.

For PSRemoting, run the same script on the elevated endpoint with local MSI paths:

```powershell
Invoke-Command -ComputerName $target -FilePath ./tools/install-sli-agent-local.ps1 -ArgumentList @($newMsi, '', 'sli-api-1', $true, $newHash, $oldMsi, $oldHash)
```

For SSH, stage the trusted script and packages on the endpoint and use an elevated account:

```powershell
ssh $target "powershell.exe -NoProfile -NonInteractive -File C:/SLI-Bootstrap/install-sli-agent-local.ps1 -Upgrade -MsiPath C:/SLI-Bootstrap/new.msi -MsiSha256 $newHash -PreviousMsiPath C:/SLI-Bootstrap/previous.msi -PreviousMsiSha256 $oldHash"
```

No interactive UAC is available remotely.
These contracts and unit tests do not establish installed Windows acceptance.

### Build the artifact

Use 64-bit PowerShell 5.1 in an x64 MSVC developer environment with tools
`14.44.35207` and Windows SDK `10.0.26100.0`, preinstalled on the Windows build
worker. [The lock file](../../tools/msi/toolchain.lock.json) declares exact Python,
WiX and Windows wheel filenames, versions and SHA-256 digests, with provenance
links. Stage all six inputs in an offline input directory. The build verifies
each archive before extraction, lays out pywin32/native DLLs explicitly and
checks imports with the embedded interpreter. It does not execute pip/postinstall
or fetch wheels. CPython and wheel license metadata are included in the payload.

```powershell
./tools/build-sli-agent-msi.ps1 -InputDirectory C:\SLI-Build\inputs `
  -OutputDirectory C:\SLI-Build\artifacts
```

The version comes from the checkout's `VERSION`. Calendar `YYYY.minor.patch`
maps to `YYYY-2000.minor.patch` for MSI (for example, `2026.10.1` → `26.10.1`);
the embedded agent reports the full build version. Non-calendar versions retain
their three fields within MSI limits (255/255/65535). An explicit `-ProductVersion`
must match this derived value; an independent version override is rejected.
Optional `-DownloadToolchain` downloads only the pinned WiX/Python archives and
still verifies SHA-256. The output is the MSI and its `.sha256` sidecar; failures
terminate the build. The artifact is unsigned; signing credentials are not part
of this repository or build. Linux unit/structure tests do not establish Windows
acceptance. Before release, verify clean offline Windows without Python,
SCM startup/native imports, reboot without login, enrollment, repair/account
preservation, failed-install rollback and uninstall readback (service/process
and secret directories absent). No installed acceptance is claimed here.

## Manual alternative: prepare the server and Windows host

1. Complete server installation and apply its current migration chain through
   the standard executor. Prepare the offline root and online issuer using
   [CA provisioning](../agent-enrollment.md#offline-root-and-online-issuer).
   Never mount the root private key in the server.
2. Configure [the agent overlay](../../deploy/linux/docker-compose.agent.yml)
   with protected host CA/issuer files as described in
   [the workstation procedure](../agent-enrollment.md#тестовая-рабочая-станция).
   Mount the issuer only in the API and restart its TLS listener. Agent TLS
   must reach SLI intact: use [TLS passthrough](../agent-enrollment.md#reverse-proxy),
   not client-certificate forwarding headers.
3. Install supported Python (3.11+) on Windows and the
   [agent-only dependencies](../../sli_agent/requirements.txt).
   Deploy the trusted `sli_agent` and `sli_collect` packages where that interpreter
   can import them without an interactive user's current directory.
4. Choose LocalSystem or an operator-selected service identity. Grant only
   required local log access, Log on as a service, read/execute on Python/packages,
   read on configuration/CA and write on protected state. Keep clocks synchronized.

## Configure and enroll

Place configuration at `%ProgramData%\SLI\Agent\agent.json`, and the public
HTTPS server CA bundle at the path it names. Replace the placeholder endpoint;
its name must match the server certificate.

```json
{
  "server_url": "https://example.invalid:8443",
  "ca_bundle": "C:/ProgramData/SLI/Agent/server-ca.pem",
  "state_dir": "C:/ProgramData/SLI/Agent/state",
  "collection_enabled": false,
  "event_channels": []
}
```

Protect config/CA against nonadministrative writes and state with a protected
DACL for the chosen identity and SYSTEM. Prepare/enroll under that identity;
explicitly hand over any administrator-created restricted state files.
Using the installed interpreter (replace the example path):

```powershell
$agentPython = 'C:/SLI-Agent/venv/Scripts/python.exe'
$agentConfig = Join-Path $env:ProgramData 'SLI/Agent/agent.json'
& $agentPython -m sli_agent --config $agentConfig prepare
& $agentPython -m sli_agent --config $agentConfig enroll
```

Between `prepare` and `enroll`, the platform owner approves the printed host
UUID and SPKI fingerprint and issues a short-lived, single-use token through the
[owner API](../agent-enrollment.md#api). Enter the token only at the hidden
`enroll` prompt; never pass it in arguments, environment, config or transcripts.
The host UUID is not a hostname or proof of AD identity.

## Register the service and authorize collection

In elevated PowerShell from the trusted checkout, review and run
[the service installer](../../tools/install-sli-agent.ps1) first without
`-Install`, then with it:

```powershell
./tools/install-sli-agent.ps1 -PythonExecutable $agentPython -ConfigPath $agentConfig
./tools/install-sli-agent.ps1 -PythonExecutable $agentPython -ConfigPath $agentConfig -Install
```

Registration leaves `SLIAgent` stopped with manual startup. Finish account and
ACL checks in Windows Services before starting it. The installer does not
request/store a service-account password or assume gMSA.
For a console-only workstation evaluation, use
[agent-dev-run.ps1](../../tools/agent-dev-run.ps1) and the enrollment procedure
instead of installing the service.

The owner must separately enable the server plugin and assign an approved
module/policy. For `sli.workstations`, use the
[workstation enrollment procedure](../agent-enrollment.md#тестовая-рабочая-станция).
Local `collection_enabled=false` controls the legacy Event Log module; it does
not disable a server-assigned workstation module. Check Windows audit settings
and channel permissions separately; installation does not change audit policy.

## Verify, stop and update

Confirm service/console state, safe `state/status.json` codes, last-seen in the
owner registry and the assigned modules. A `committed` receipt means durable
inbox storage, not completed projection or report delivery. Follow the
[readback procedure](../agent-enrollment.md#подтверждение-результата-и-остановка)
for controlled-event verification, replay/restart checks and safe stopping.
Stop the service in Windows Services (or Ctrl+C for console mode); disable
module assignments/plugin projection separately as needed. Preserve state,
spool and receipts on failures; never delete them to force apparent progress.

The server Docker updater rejects agent packages
and does not install/update a Windows service. Use only trusted compatible
agent distributions through the reviewed Windows installation path; keep
identity/state intact. These instructions do not establish installed acceptance.
