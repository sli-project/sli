"""Route PR changes to classes with relevant nightly-only tests."""
import sys


# Each area lists repository-relative paths (directories end with "/") and
# test classes. The shard planner admits only their nightly-only methods.
RISKS = {
    "migrations": (
        ("config/postgres_migrations/",),
        (
            "Sli.Server.Tests.Agents.FileAuditConsumerDatabaseTests",
            "Sli.Server.Tests.Jobs.CoreJobRecovery322Tests",
            "Sli.Server.Tests.Operations.OperationsStreamPostgresTests",
            "Sli.Server.Tests.Semantic.SemanticEventIdIndexPostgresTests",
            "Sli.Server.Tests.SemanticLargeDatabaseTests",
            "Sli.Server.Tests.Storage.DbLoadIndexesPostgresTests",
            "Sli.Server.Tests.Workstations.WorkstationInventoryJobPostgresTests",
        ),
    ),
    "access": (
        ("server-dotnet/src/Sli.Server/Auth/", "server-dotnet/src/Sli.Server/Access/"),
        ("Sli.Server.Tests.Reporting.ReportStudioTests",),
    ),
    "recovery": (
        ("deploy/linux/native_backup.py", "deploy/linux/restore_existing.py", "deploy/linux/native_upgrade.py"),
        (
            "Sli.Server.Tests.Jobs.CoreJobRecovery322Tests",
            "Sli.Server.Tests.Operations.OperationsStreamPostgresTests",
        ),
    ),
    "storage": (
        ("server-dotnet/src/Sli.Server/Storage/",),
        (
            "Sli.Server.Tests.DbLoadScreensPostgresTests",
            "Sli.Server.Tests.Semantic.PasswordCommitCostPostgresTests",
            "Sli.Server.Tests.Semantic.PasswordStateAndStepPostgresTests",
            "Sli.Server.Tests.Semantic.SemanticEventIdIndexPostgresTests",
            "Sli.Server.Tests.SemanticLargeDatabaseTests",
            "Sli.Server.Tests.Storage.DbLoadIndexesPostgresTests",
        ),
    ),
}


def changed_areas(paths: list[str]) -> list[str]:
    return [
        area for area, (patterns, _) in RISKS.items()
        if any(path.startswith(pattern) if pattern.endswith("/") else path == pattern
               for path in paths for pattern in patterns)
    ]


def risk_classes(areas: list[str]) -> set[str]:
    if unknown := set(areas) - RISKS.keys():
        raise ValueError(f"Unknown CI risk areas: {', '.join(sorted(unknown))}")
    return {name for area in areas for name in RISKS[area][1]}


if __name__ == "__main__":
    paths = sys.stdin.buffer.read().decode("utf-8", errors="surrogateescape").split("\0")
    print(" ".join(changed_areas(paths)))
