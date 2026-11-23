# Troubleshooting

[Русская версия](../ru/troubleshooting.md) · [Guide index](README.md)

Start with the first step that failed. Record its time and time zone, the
installed release and the message or result code. For problems that appeared
during an update, start with [Verify or resume the update](upgrade.md#verify-or-resume-the-update).

| Symptom | Start with |
| --- | --- |
| Browser cannot connect or sign in | [HTTPS and sign-in](#https-and-sign-in) |
| Server page loads, but a section shows an error | [Server checks](#server-checks) |
| Agent is offline, receiving fails, or reports are empty | [Agent checks](#agent-checks) |
| Telegram chat or notification is missing | [Telegram checks](#telegram-checks) |
| Backup is skipped or the disk is filling | [Storage checks](#storage-checks) |

## HTTPS and sign-in

Use the exact HTTPS address printed by setup, including the port if one was
shown. Confirm that name resolution and the firewall allow that connection
from the browser. For a certificate error, compare the hostname and the
public CA fingerprint with the [first sign-in procedure](install.md#first-sign-in).
Use only the CA verified from the trusted server console.

If you can reach the sign-in screen, check the account name and whether the
account is active. If SLI reports too many attempts, wait for the displayed
retry interval before trying again. Ask a user administrator to reset an
active account's password when needed. For loss of the platform owner's
password, use the
[owner recovery instructions](install.md#optional-setup-settings)
from the Debian console.

If a menu item is missing or a page says access is denied, review **My
access** at `/app/access-user`. Have the administrator check the role and
required capability or report permission for the intended domain and action.

## Server checks

On Debian, these commands read the native service state and recent logs.

```sh
systemctl status sli-dotnet.target sli-postgresql.service sli-dotnet-api.service
sudo journalctl -u sli-postgresql.service -u sli-dotnet-api.service -u sli-ready.service -n 100 --no-pager
```

Test the readiness route with the installation's CA. In this example, replace
`sli.example.test:8443` with the HTTPS host and port that setup printed.
Run the check from a host that can reach that address and has a verified
copy of the CA at the indicated path.

```sh
curl --fail --show-error --silent --cacert /var/lib/sli/tls-ca.crt https://sli.example.test:8443/api/health/ready
```

If readiness fails, use the unit messages and timestamps to identify the
failing service or database dependency. If it succeeds, open **System
status** for the specific source or worker status. For a single failing
panel, record its name and retry. Overall readiness only covers the
server's readiness checks.

## Agent checks

1. On Windows, check the service and the HTTPS port. Substitute the installed
   server's hostname and port for the examples.

   ```powershell
   Get-Service -Name SLIAgentNet
   Test-NetConnection -ComputerName sli.example.test -Port 8443
   ```

   A successful TCP test checks reachability. For a certificate or enrollment
   error, verify HTTPS trust and command validity in the
   [Windows agent guide](agents.md). If the service is absent, check
   which MSI was installed. Review **Last contact** in SLI after checking
   the service and connection.

2. If contact is recent but no packets arrive, open the agent and check
   collection pause state, enabled modules, desired and applied revisions and
   Windows audit details. Compare the source's last data and its configured
   interval. Review the agent's source diagnostics for an unreadable Windows
   channel or a reported gap.
3. If packets arrive but the source or report stays stale, check import or
   delivery diagnostics and the processing worker on **System status**.
   Use a report period and domain that cover the accepted input and check
   report permissions. A quiet reporting period is possible even while
   collection is healthy.

## Telegram checks

- **Bot verification fails.** Check the token in the Telegram setup panel and
  connectivity from the Debian server. Check the
  [native proxy or VPN configuration](admin.md#proxy-or-vpn) before verifying
  the bot again.
- **The chat list is empty.** Send `/start` again from the intended chat,
  then select **Find chat** and save the destination.
- **The test control is disabled.** Check your configuration permission,
  the verified bot token, the bound destination and the **Enabled** switch.
  Wait for a pending test to finish before submitting another. If a test
  fails to start, confirm your Telegram rule is enabled under **Rules**.
- **The test was submitted.** Open the matching job in the **Journal**.
  Check the error or retry time. If the send outcome is unknown, look in
  the chat before retrying. If the provider accepted the job, verify
  delivery in the chat. A test without sending has state `dry_run`.
- **The test works but no problem arrives.** Check the enabled delivery
  rule and recipient and use the journal to check the matching problem.
  Historical import and replay can suppress delivery. Use an eligible live
  problem to verify ongoing notifications.

## Storage checks

Compare the volume row in **Storage** with the actual free space. On Debian
check the mounts and free space for the database and native backup directories.

```sh
findmnt -T /srv/sli-db
findmnt -T /var/backups/sli/native
df -h /srv/sli-db /var/backups/sli/native
```

Check the last backup result and the journal for the affected service with
the [native backup procedure](upgrade.md#native-backups). A space
or volume refusal identifies the directory or volume to inspect. If a mount
is missing, restore the intended mount before writing more data to that
path. Use the [space requirements](upgrade.md#check-free-space) to
plan headroom for an upgrade or drill. PostgreSQL data, backup manifests and
pending update checkpoints should be kept intact while diagnosing the issue.

## Collect a support report

Gather the release and commit, symptom and timestamps, affected section or
worker, and relevant result codes or short log excerpts. Include the name of
the failed step and any meaningful states that still work. Before sharing a
diagnostic export or journal excerpt, remove credentials, private keys, host
details and directory data that the recipient does not need.
