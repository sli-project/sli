# Work screens

[Русская версия](../ru/user-guide.md) · [Guide index](README.md)

These guides describe the screens shipped in beta source `a164f00`. Paths are
relative to your SLI server's HTTPS address. Visible data, detail panels and
actions depend on the current user's effective access and the available
source data.

| Screen | Path |
| --- | --- |
| [Home](screens/home.md) | `/app/` |
| [Problems](screens/problems.md) | `/app/report/security.problems` |
| [Event journal](screens/event-journal.md) | `/app/report/events.journal` |
| [Domain changes](screens/domain-changes.md) | `/app/report/security.events.chains` |
| [AD state](screens/ad-state.md) | `/app/report/ad.infrastructure` |
| [Users](screens/users.md) | `/app/report/ad.users.v2` |
| [Computers](screens/computers.md) | `/app/report/ad.computers.v6` |
| [Group policies](screens/gpo.md) | `/app/report/ad.gpo.v2` |

The [detection catalog](detections.md) explains how to review ten security
signals using retained observations. For account permissions and data-source
health, see [Administration](admin.md) and
[Troubleshooting](troubleshooting.md).
