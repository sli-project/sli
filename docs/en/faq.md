# Frequently asked questions

[Русская версия](../ru/faq.md) · [Guide index](README.md)

## Which installer should I use?

Use the [Debian beta archive](install.md#install-from-the-archive) for a
native installation. The [APT path](install.md#install-from-the-apt-repository)
is available after publication of the signed repository. For an existing
server, follow [Upgrade](upgrade.md#upgrade) using your current
delivery path.

## Why is a page or action missing?

Menus depend on effective access. Check **My access** at `/app/access-user`
and ask an administrator to check the capability, report permission and domain.
The user form offers Observer and Administrator. Owner-only actions have a
separate check. See [Users and roles](admin.md#users-and-roles).

## When is a connected agent ready to supply reports?

A recent agent contact confirms a connection. Then check for accepted
packets, processing and the report's date range and domain. AD and GPO have
their own source data. See [Agent checks](troubleshooting.md#agent-checks)
to identify the step that is still waiting.

## What does a successful Telegram test confirm?

Provider acceptance is recorded under `accepted` in the **Journal**.
Verify receipt in the bound chat. To check ongoing delivery, review the rule
created when the chat was bound and look for an eligible live problem. Follow
[Telegram notifications](admin.md#telegram-notifications).

## Does changing AD/GPO retention change how long everything is stored?

The **AD/GPO change history** setting controls retained AD/GPO change history.
A source event, a derived record and a backup can have distinct availability.
See [Storage](admin.md#storage) for the setting and the volume figures.

## How do I know a backup can be restored?

Check the saved backup result, then run an isolated restore drill and match
its result to that backup ID and manifest hash. The
[restore drill procedure](upgrade.md#run-a-restore-drill) gives the
required status and fields. A recent backup timestamp in **Storage** only
identifies when a copy was made.

## What should I check before contacting support?

Find the affected step in [Troubleshooting](troubleshooting.md). Include the
release, time, section, result code and a short, reviewed diagnostic excerpt.
