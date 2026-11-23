# SLI Platform — Security Log Intelligence

[Русская версия](README.ru.md)

> **Status: in development.** SLI is not ready for use yet. The first beta is planned for **1 December 2026**.

SLI collects and analyses Windows security events and Active Directory data.
The .NET server handles ingestion, access control, reports and alerts. The first
beta covers Active Directory checks, including Group Policy, and detects attacks
in domain controller logs.

Windows agents read approved sources and deliver bounded batches over HTTPS.
The core registers agents, authenticates them with mTLS and assigns modules.
SLI reads surveyed systems; source access and collection are explicitly
configured. Installing the server alone does not enable collection.

## Architecture

The first beta uses native Debian packages managed by systemd. PostgreSQL runs
on the host.
The stack includes the HTTPS API serving the React/TypeScript UI, migration and
backup services, and workers for post-collection processing, projections,
semantics, entity state, storage lifecycle, AD snapshots and remote access.

- **PostgreSQL 18** is the authoritative runtime database for operational data,
  identities, permissions, job state and migration history.
- **Agents** receive a server URL, public trust bundle and assigned policies;
  they need no database credentials.
- **Core and plugins** separate shared mechanisms from source-specific knowledge.

## Installation

1. [Download and verify the beta archive](docs/en/install.md#download-and-verify-the-archive).
2. [Run the installer](docs/en/install.md#run-the-installer) on a clean Debian 13 amd64 host.
3. [Sign in with the initial owner account](docs/en/install.md#first-sign-in) and [connect your Windows agent](docs/en/agents.md).

### Install from the APT repository

After publication, follow the [signed APT repository instructions](docs/en/install.md#install-from-the-apt-repository).

### Install from the archive

[Install from the archive](docs/en/install.md#install-from-the-archive).

### First sign-in

[First sign-in](docs/en/install.md#first-sign-in).

### Optional setup settings

[Optional setup settings](docs/en/install.md#optional-setup-settings).

### Windows agent

[Windows agent](docs/en/agents.md).

### Native backups

[Native backups](docs/en/upgrade.md#native-backups).

### Restore and rollback

[Restore and rollback](docs/en/upgrade.md#restore-and-rollback).

### Reinstallation with retained data

[Reinstallation with retained data](docs/en/upgrade.md#reinstallation-with-retained-data).

### Uninstall

[Uninstall](docs/en/upgrade.md#uninstall).

## Upgrade

[Upgrade](docs/en/upgrade.md#upgrade).

## Administration

[Administration](docs/en/admin.md) covers system status, agents, local users, notifications and storage.

## Security model

HTTPS protects operator and agent connections. The generated installation command
uses a short-lived registration key with a per-computer limit. Manual enrollment
uses an owner-approved key fingerprint and a single-use token. Agent requests
require mTLS and registry checks. Platform permissions and scope govern reports
and evidence.
Runtime database roles have bounded privileges; migrations use a separate
administrative path. Keep passwords, tokens and private keys in protected files
outside the repository. Do not log secrets or private directory data.

Collection is read-only and bounded. Storage deletion and warm-copy admission
remain closed until explicitly approved through the operational gates.
See the [security policy](SECURITY.md) and the [administrator guide](docs/en/admin.md#users-and-roles).

## Documentation

[English guides](docs/en/README.md) · [Руководства на русском](docs/ru/README.md)

| Topic | English | Русский |
| --- | --- | --- |
| Server installation and first sign-in | [Guide](docs/en/install.md) | [Руководство](docs/ru/install.md) |
| Update, backups, rollback and restore | [Guide](docs/en/upgrade.md) | [Руководство](docs/ru/upgrade.md) |
| Connect a Windows agent | [Guide](docs/en/agents.md) | [Руководство](docs/ru/agents.md) |
| Administration | [Guide](docs/en/admin.md) | [Руководство](docs/ru/admin.md) |
| Troubleshooting | [Guide](docs/en/troubleshooting.md) | [Руководство](docs/ru/troubleshooting.md) |
| Frequently asked questions | [FAQ](docs/en/faq.md) | [Частые вопросы](docs/ru/faq.md) |

- [Contributing, checks and migrations](CONTRIBUTING.md)
- [Work screens](docs/en/user-guide.md)
- [Detection catalog](docs/en/detections.md)

## License

SLI Platform and its agent are licensed under [Apache-2.0](LICENSE).
Separately licensed dependencies and Sigma content are listed in [NOTICE](NOTICE).
