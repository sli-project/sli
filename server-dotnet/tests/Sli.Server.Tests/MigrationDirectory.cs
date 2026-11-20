using System.Text.RegularExpressions;

namespace Sli.Server.Tests;

internal static class MigrationDirectory
{
    internal static (int Version, string Name, string Path)[] Read(int startingAt = 0)
    {
        return Directory.GetFiles(System.IO.Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations"), "*.sql")
            .Select(path => (Path: path, Match: Regex.Match(System.IO.Path.GetFileName(path), @"^(\d+)_([a-z0-9_]+)\.sql$")))
            .Where(item => item.Match.Success && !item.Match.Groups[2].Value.EndsWith("_rollback", StringComparison.Ordinal))
            .Select(item => (Version: int.Parse(item.Match.Groups[1].Value), Name: item.Match.Groups[2].Value, item.Path))
            .Where(item => item.Version >= startingAt)
            .OrderBy(item => item.Version).ToArray();
    }
}
