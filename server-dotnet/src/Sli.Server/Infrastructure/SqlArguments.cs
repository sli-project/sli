namespace Sli.Server.Infrastructure;

internal static class SqlArguments
{
    internal static void Validate(object?[] values)
    {
        // C# array covariance lets a lone string[] replace the params object[]
        // itself. Require an explicit list (e.g. [(object)ids]) before binding SQL.
        if (values.GetType() != typeof(object[]))
            throw new ArgumentException("SQL array parameters must be wrapped in an object[] argument list or cast to object.", nameof(values));
    }
}
