# Administration

[Русская версия](../ru/administration.md) · [Guide index](README.md)

In the native Debian beta, open **Administration** after signing in. The paths
below are relative to the HTTPS address of your SLI server. Menu entries and
actions depend on the current account's permissions.

| Page | Path | What to check |
| --- | --- | --- |
| System status | `/app/admin/status` | Release, sources, server services and disk |
| Agents | `/app/agents` | Windows connections, collection policy and diagnostics |
| Users & roles | `/app/access` | Local users, roles and activity log |
| Notifications | `/app/notifications` | Channels, rules and delivery journal |
| Storage | `/app/operations` | PostgreSQL size, volume usage and AD/GPO retention |

## System status

The header shows the installed release, commit and installation date when
available. Use **Download diagnostics** to save a server report for
troubleshooting. Review the file before sharing it.

- **Sources** shows data delivery by monitored source. Compare the latest data
  time with the expected collection interval. A recent contact proves that
  the agent reached the server. An accepted packet and its processing are
  separate checks.
- **Server services** reflects worker observations. Check which worker reports
  an issue and when it was last seen. A disabled feature, missing observation,
  and a failed worker call for different checks.
- **Checks not running** appears when the service has evidence of missing
  Windows audit settings. Follow the link to the agent and review its
  applicable policy and the affected checks.
- **Disk** summarizes the volume. Open **Storage** for database size, growth
  and the backup timestamp when available.

The page queries sections independently. If a section fails to load, retry
that section and record which one failed. Source collection, data processing
and backups can each require their own check.

For host administration, an operator with Debian sudo access can run
`sudo sli-setup --web-console` to enable Cockpit on port 9090. Open **Server
console** on the status page when the link is available and sign in with the
Linux account. SLI user credentials are separate.

## Agents

Open a row to review **Last contact**, the collection policy, module
settings and any available Windows audit, event-log or delivery diagnostics.
Compare the desired and applied policy revisions after a change. If the agent
has yet to apply the new revision, check its connection before repeating the
change. After resuming paused collection, verify that new packets arrive and
are processed.

The page requires the platform owner or `access.manage`. Some actions, such
as group deployment, permanent removal and sequence recovery, are reserved
for the platform owner. For enrollment and replacement, follow the
[Windows agent guide](windows-agent.md). For an agent that has stopped
reporting, see [Agent checks](troubleshooting.md#agent-checks).

## Users and roles

The **Users & roles** page requires an administrator account with
`access.manage`. On **Users**, select **Add user**, enter a local username,
choose a role and set a password of at least 12 characters. Use a private
channel to give the password to its recipient. Use a separate named account
for each person so that the activity log identifies their actions.

| Selectable role | Scope |
| --- | --- |
| Observer (`viewer`) | Works with the screens, reports and evidence available under the user's effective permissions. |
| Administrator (`admin`) | Can administer accounts and other areas when the required capabilities and resource permissions allow it. |

Existing users with the legacy `operator` role may appear as **Operator**.
The role selector offers Observer and Administrator for assignment. Platform
ownership is a separate permission with additional actions. An administrator
role alone does not assign it or grant unrestricted data access. Use the
account's **My access** page (`/app/access-user`) to check effective access.

From the user's row, you can change the role, reset the password of an active
user, or enable or disable the account. The server rejects disabling the
signed-in account and disabling or demoting the last active administrator.
Disabling an account ends its sessions. Use **Activity log** to review the
actor, action, target, result and time of an access change.

## Telegram notifications

Open **Notifications** → **Channels** → **Telegram**. Channel setup requires
administrator access with `access.manage` and permission to configure the
channel. Use a bot under your organization's control.

1. Paste the token from `@BotFather` in the Telegram setup panel and select
   **Verify**. Enter a Telegram proxy there if the server needs one to reach
   Telegram. Keep the token and any proxy credentials out of diagnostics.
2. Send `/start` to the bot from the intended chat. In SLI, select **Find
   chat**, choose the chat and select **Save**. Binding enables the channel
   and sets up a rule for your account. Check the destination shown in the
   panel and confirm that **Enabled** is on.
3. Select **Send test** and watch the result for that job. In the **Journal**,
   filter by Telegram and open the matching job to review its result.
   `accepted` indicates provider acceptance. Confirm receipt in the chat.
4. For ongoing problem notifications, open **Rules** and check the Telegram
   rule for your account. Open the existing rule to change its enabled state.
   Check a subsequent eligible live problem in the **Journal**. The test
   covers transport to the bound chat.

An empty chat list, a disabled test control and an unknown send outcome have
different remedies. See [Telegram checks](troubleshooting.md#telegram-checks).

## Storage

**Storage** requires `operations.view` and is available to administrators
and permitted accounts with the legacy Operator role. The database row
measures PostgreSQL.
The partition row gives volume usage and free space. Use the partition's
numbers for capacity planning. Growth and forecast appear when measured data
is available. A blank value means the measurement is unavailable.

In **Retention**, an administrator with settings access can set **AD/GPO
change history** to an integer from 7 to 3650 days. The default is 365 days.
This controls retained AD/GPO change history. Copies of source evidence and
backups have their own lifecycles. Before shortening history, review the time
range required for investigations and check the last qualifying backup.

The latest backup timestamp, when shown, helps locate the backup run. Use the
[backup and recovery guide](upgrade-recovery.md#run-a-restore-drill)
to check the backup result and evidence from a restore drill. See
[Storage checks](troubleshooting.md#storage-checks) if growth or free space
requires attention.
