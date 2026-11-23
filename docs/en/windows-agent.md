# Connect a Windows agent

[Русская версия](../ru/windows-agent.md) · [Guide index](README.md)

Use the x64 .NET agent provided by the SLI server. Make sure the Windows
domain controller can reach the server directly over HTTPS.

## Register the agent

1. Sign in as the platform owner or with the `access.manage` permission.
   Choose **Add agent** on **Home** when no agent is registered, or open
   **Agents → Add agent**.
2. Enter the HTTPS origin reachable directly from Windows, for example
   `https://sli.example.test:8443`, without `/app`. The name or IP must be in
   the server certificate. The command connects without a proxy or redirects.
   Select 1–100 computers (default 1). Leave audit
   management on to let SLI configure Windows auditing on the domain controller.
   If the address is rejected, use a name or IP listed in the error. If the
   form cannot load settings or the package, check the server's MSI and
   certificate and reopen the form.
3. Select **Create command** and run the copied line in 64-bit PowerShell as
   administrator on the domain controller. The UI saves the address. The line
   contains a secret registration key valid for one hour, with one registration
   per computer up to the selected count. Share it only with the administrator
   installing the agent. Create a new command if it expires or reaches its limit.
   The script verifies TLS and the MSI hash before installing. For a signed
   MSI it also verifies Authenticode.

## Confirm the first data

1. In **Agents**, check **Last contact** after the service starts.
2. Open **System status → First run** at `/app/admin/status` and wait for
   **First data: received at …**. Then check **Sources → Latest data** for
   the computer on the same page. Check the AD and Group Policy reports
   separately. Their snapshots require a confirmed domain scope for the
   controller.
3. To verify notifications, open **Notifications → Channels**
   (`/app/notifications?tab=channels`), set up a channel and select **Send test**.
   Confirm that the test message arrives.

## Generate a command from Debian

On the server, `sudo sli-agent-command` uses the saved address. The example
sets an address for the current command only.

```sh
sudo sli-agent-command --server-url https://sli.example.test:8443 --count 1
```

Replace the example with your HTTPS origin. Pass `--server-url` each time if
no address is saved. `--count` accepts 1–100 and `--no-audit` leaves audit
management off.

## Verify an MSI download

Verify a standalone download in PowerShell on a computer that trusts the server
CA. Substitute your server's HTTPS origin in the URL.

```powershell
curl.exe -fsS -D - -o SliAgent.msi https://sli.example.test:8443/api/v1/agent/installer/SliAgent.msi
Get-FileHash .\SliAgent.msi -Algorithm SHA256
```

Compare the printed `X-SLI-Package-SHA256` header with the file hash. Use the
generated command for first registration.

## Replace a standard installation

For a planned replacement of a standard MSI installation, issue a new command
for that computer and verify its contact and first data again. If the existing
registration requires owner approval, obtain it before replacement. If the
script reports a custom state directory, `agent.json` or a remaining old
service, keep its configuration and state and resolve the reported conflict
before retrying. Keep the previous MSI available. If replacement fails after
removing it, restoring the old Windows service may require that MSI.

## Remove the agent

On Windows, remove **SLI Agent .NET** from **Installed apps**. Its service is
`SLIAgentNet`. The entry **SLI Agent** belongs to the older MSI. To revoke the
server registration as well, open the computer in **Agents** and choose
**Disable agent**.
