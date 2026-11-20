using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Npgsql;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

public sealed class PluginRuntimeAdmissionExecutorTests
{
    private static readonly Guid LeaseUid = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly DateTimeOffset Expires = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static object[] Admission(string component = PluginRuntimeAdmissionExecutor.Acquisition, string mode = "open") =>
        [LeaseUid, component, mode, Expires];
    private static PluginComponentLease Lease(string component = PluginRuntimeAdmissionExecutor.Acquisition) => new(LeaseUid, component, "open", Expires);

    [Theory]
    [InlineData(PluginRuntimeAdmissionExecutor.Acquisition, "source_contact", "adlog_radius_accounting_worker", "worker-1")]
    [InlineData(PluginRuntimeAdmissionExecutor.Consumer, "delivery_claim", "adlog_radius_session_consumer", "consumer-1")]
    [InlineData(PluginRuntimeAdmissionExecutor.Consumer, "delivery_claim", "adlog_radius_session_consumer", " fixture'; select 1; -- ")]
    public async Task Acquire_uses_one_parameterized_exact_call(string component, string kind, string role, string holder)
    {
        await using var db = new Connection(Admission(component));
        var result = await PluginRuntimeAdmissionExecutor.AcquireAsync(db, LeaseUid, component, holder, Ct);
        Assert.Equal(new(LeaseUid, component, "open", Expires), result);
        Assert.Equal(2, db.Calls.Count);
        Assert.Equal("set local role " + role, db.Calls[0].Sql);
        Assert.Empty(db.Calls[0].Parameters);
        Assert.Equal("select lease_uid,component_id,admission_mode,expires_at_utc\nfrom public.acquire_plugin_component_lease_v1($1,$2,$3,$4,$5)", db.Calls[1].Sql.Replace("\r\n", "\n"));
        Assert.Equal(new object[] { LeaseUid, "sli.remote-access", component, kind, holder }, db.Calls[1].Parameters);
        Assert.Equal(0, db.Commits);
        Assert.Equal(0, db.Rollbacks);
    }

    [Fact]
    public async Task Release_validates_outcome_before_database()
    {
        await using var db = new Connection([true]);
        var error = await Assert.ThrowsAsync<VpnInputException>(() => PluginRuntimeAdmissionExecutor.ReleaseAsync(db, Lease(), "worker-1", "deleted", Ct));
        Assert.Equal("component_lease_outcome_invalid", error.Message);
        Assert.Empty(db.Calls);
    }

    [Theory]
    [InlineData(PluginRuntimeAdmissionExecutor.Consumer, "adlog_radius_session_consumer", "completed", true)]
    [InlineData(PluginRuntimeAdmissionExecutor.Acquisition, "adlog_radius_accounting_worker", "failed", true)]
    [InlineData(PluginRuntimeAdmissionExecutor.Consumer, "adlog_radius_session_consumer", "cancelled", false)]
    public async Task Release_activates_only_the_component_role(string component, string role, string outcome, bool released)
    {
        await using var db = new Connection([released]);
        Assert.Equal(released, await PluginRuntimeAdmissionExecutor.ReleaseAsync(db, Lease(component), "consumer-1", outcome, Ct));
        Assert.Equal(2, db.Calls.Count);
        Assert.Equal("set local role " + role, db.Calls[0].Sql);
        Assert.Empty(db.Calls[0].Parameters);
        Assert.Equal("select public.release_plugin_component_lease_v1($1,$2,$3)", db.Calls[1].Sql);
        Assert.Equal(new object[] { LeaseUid, "consumer-1", outcome }, db.Calls[1].Parameters);
    }

    [Theory]
    [InlineData(PluginRuntimeAdmissionExecutor.Acquisition)]
    [InlineData(PluginRuntimeAdmissionExecutor.Consumer)]
    public async Task Scope_commits_admission_before_work_and_completion(string component)
    {
        await using var db = new Connection(Admission(component), [true]);
        await PluginRuntimeAdmissionExecutor.RunAsync(db, component, "worker-1", (lease, transaction, _) => {
            Assert.Equal(LeaseUid, lease.LeaseUid);
            Assert.Equal(1, db.Commits);
            Assert.Same(db.ActiveTransaction, transaction);
            db.Steps.Add("work");
            return Task.CompletedTask;
        }, Ct, LeaseUid);
        Assert.Equal(2, db.Commits);
        Assert.Equal(0, db.Rollbacks);
        Assert.Equal(new[] { "begin", "role", "acquire", "commit", "begin", "work", "role", "release:completed", "commit" }, db.Steps);
        Assert.NotSame(db.Calls[1].Transaction, db.Calls[3].Transaction);
        Assert.Null(db.ActiveTransaction);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Scope_releases_failed_after_rollback_and_preserves_the_error(bool cancelled)
    {
        await using var db = new Connection(Admission(), [true]);
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        Exception failure = cancelled ? new OperationCanceledException(stopping.Token) : new InvalidOperationException("boom");
        var thrown = await Record.ExceptionAsync(() => PluginRuntimeAdmissionExecutor.RunAsync(db, PluginRuntimeAdmissionExecutor.Acquisition, "worker-1", (_, _, _) => {
            Assert.Equal(1, db.Commits);
            db.Steps.Add("work");
            if (cancelled) stopping.Cancel();
            return Task.FromException(failure);
        }, stopping.Token, LeaseUid));
        Assert.Same(failure, thrown);
        Assert.Equal(2, db.Commits);
        Assert.Equal(1, db.Rollbacks);
        Assert.Equal(new[] { "begin", "role", "acquire", "commit", "begin", "work", "rollback", "begin", "role", "release:failed", "commit" }, db.Steps);
        Assert.Equal(new object[] { LeaseUid, "worker-1", "failed" }, db.Calls[3].Parameters);
        Assert.Null(db.ActiveTransaction);
    }

    [Fact]
    public async Task Publisher_acquires_and_releases_without_changing_role_or_committing()
    {
        await using var db = new Connection(Admission(PluginRuntimeAdmissionExecutor.Consumer), [true]);
        // An enclosing result fence owns this transaction, including all work.
        await using var publisher = await db.BeginTransactionAsync(Ct);
        var lease = await PluginRuntimeAdmissionExecutor.AcquireAsync(db, LeaseUid, PluginRuntimeAdmissionExecutor.Consumer, "core-job:fixture", Ct, activateRole: false);
        Assert.Single(db.Calls);
        Assert.Contains("acquire_plugin_component_lease_v1", db.Calls[0].Sql);
        Assert.Equal(new object[] { LeaseUid, "sli.remote-access", PluginRuntimeAdmissionExecutor.Consumer, "delivery_claim", "core-job:fixture" }, db.Calls[0].Parameters);
        Assert.True(await PluginRuntimeAdmissionExecutor.ReleaseAsync(db, lease, "core-job:fixture", "completed", Ct, activateRole: false));
        Assert.Equal(2, db.Calls.Count);
        Assert.Contains("release_plugin_component_lease_v1", db.Calls[1].Sql);
        Assert.Equal(new object[] { LeaseUid, "core-job:fixture", "completed" }, db.Calls[1].Parameters);
        Assert.Equal(0, db.Commits);
        Assert.Equal(0, db.Rollbacks);
        Assert.Same(publisher, db.ActiveTransaction);
    }

    [Theory]
    [InlineData("unknown", "worker-1")]
    [InlineData("radius-acquisition; reset role", "worker-1")]
    [InlineData(PluginRuntimeAdmissionExecutor.Consumer, " ")]
    public async Task Invalid_requests_never_contact_database(string component, string holder)
    {
        await using var db = new Connection();
        var error = await Assert.ThrowsAsync<VpnInputException>(() => PluginRuntimeAdmissionExecutor.AcquireAsync(db, LeaseUid, component, holder, Ct));
        Assert.Equal("component_lease_request_invalid", error.Message);
        Assert.Empty(db.Calls);
    }

    [Theory]
    [InlineData("missing", "component_lease_result_missing")]
    [InlineData("uid", "component_lease_result_invalid")]
    [InlineData("component", "component_lease_result_invalid")]
    [InlineData("mode", "component_lease_result_invalid")]
    [InlineData("drain_only", "component_lease_result_invalid")]
    [InlineData("timestamp", "component_lease_result_invalid")]
    [InlineData("naive", "component_lease_result_invalid")]
    [InlineData("null", "component_lease_result_invalid")]
    public async Task Acquisition_rejects_missing_or_invalid_database_result(string problem, string code)
    {
        var row = Admission();
        switch (problem) {
            case "uid": row[0] = Guid.Empty; break;
            case "component": row[1] = PluginRuntimeAdmissionExecutor.Consumer; break;
            case "mode": row[2] = "closed"; break;
            case "drain_only": row[2] = "drain_only"; break;
            case "timestamp": row[3] = "2026-01-01T00:00:00Z"; break;
            case "naive": row[3] = DateTime.SpecifyKind(Expires.DateTime, DateTimeKind.Unspecified); break;
            case "null": row[3] = DBNull.Value; break;
        }
        await using var db = new Connection(problem == "missing" ? null : row);
        var error = await Assert.ThrowsAsync<VpnInputException>(() => PluginRuntimeAdmissionExecutor.AcquireAsync(db, LeaseUid, PluginRuntimeAdmissionExecutor.Acquisition, "worker-1", Ct));
        Assert.Equal(code, error.Message);
    }

    [Fact]
    public async Task Consumer_accepts_drain_only_and_postgres_utc_timestamp()
    {
        var row = Admission(PluginRuntimeAdmissionExecutor.Consumer, "drain_only");
        row[3] = Expires.UtcDateTime;
        await using var db = new Connection(row);
        var result = await PluginRuntimeAdmissionExecutor.AcquireAsync(db, LeaseUid, PluginRuntimeAdmissionExecutor.Consumer, "consumer-1", Ct);
        Assert.Equal("drain_only", result.AdmissionMode);
        Assert.Equal(Expires, result.ExpiresAtUtc);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("null")]
    [InlineData("number")]
    public async Task Release_requires_a_boolean_database_result(string problem)
    {
        await using var db = new Connection(problem == "missing" ? null : [problem == "null" ? DBNull.Value : 1]);
        var error = await Assert.ThrowsAsync<VpnInputException>(() => PluginRuntimeAdmissionExecutor.ReleaseAsync(db, Lease(), "worker-1", "completed", Ct));
        Assert.Equal("component_lease_release_invalid", error.Message);
    }

    [Fact]
    public async Task Failed_admission_never_starts_work_or_publishes_completion()
    {
        await using var db = new Connection((object[]?)null);
        var error = await Assert.ThrowsAsync<VpnInputException>(() => PluginRuntimeAdmissionExecutor.RunAsync(db,
            PluginRuntimeAdmissionExecutor.Consumer, "consumer-1", (_, _, _) => throw new Xunit.Sdk.XunitException("work must not run"), Ct));
        Assert.Equal("component_lease_result_missing", error.Message);
        Assert.Equal(0, db.Commits);
        Assert.DoesNotContain(db.Calls, c => c.Sql.Contains("release_plugin_component_lease_v1"));
    }

    private sealed record Call(string Sql, object[] Parameters, DbTransaction? Transaction);

    // ADO recording double corresponding to the Python cursor/connection fixtures.
    private sealed class Connection(params object[]?[] rows) : DbConnection
    {
        private readonly Queue<object[]?> results = new(rows);
        internal readonly List<Call> Calls = [];
        internal readonly List<string> Steps = [];
        internal int Commits, Rollbacks;
        internal Transaction? ActiveTransaction;
        [AllowNull] public override string ConnectionString { get; set; } = "";
        public override string Database => "synthetic";
        public override string DataSource => "synthetic";
        public override string ServerVersion => "synthetic";
        public override ConnectionState State => ConnectionState.Open;
        public override void ChangeDatabase(string databaseName) => throw new NotSupportedException();
        public override void Close() { }
        public override void Open() { }
        protected override DbCommand CreateDbCommand() => new Command(this);
        protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel)
        {
            Assert.Null(ActiveTransaction);
            Steps.Add("begin");
            return ActiveTransaction = new Transaction(this, isolationLevel);
        }

        private sealed class Command(Connection owner) : DbCommand
        {
            private readonly NpgsqlCommand parameters = new();
            [AllowNull] public override string CommandText { get; set; } = "";
            public override int CommandTimeout { get; set; }
            public override CommandType CommandType { get; set; }
            public override bool DesignTimeVisible { get; set; }
            public override UpdateRowSource UpdatedRowSource { get; set; }
            protected override DbConnection? DbConnection { get; set; } = owner;
            protected override DbTransaction? DbTransaction { get; set; }
            protected override DbParameterCollection DbParameterCollection => parameters.Parameters;
            protected override DbParameter CreateDbParameter() => new NpgsqlParameter();
            public override void Cancel() => throw new NotSupportedException();
            public override void Prepare() => throw new NotSupportedException();
            public override object? ExecuteScalar() => throw new NotSupportedException();
            private object[] Record()
            {
                Assert.Equal(0, CommandTimeout);
                if (DbTransaction is not null) Assert.Same(owner.ActiveTransaction, DbTransaction);
                var values = Parameters.Cast<DbParameter>().Select(p => p.Value!).ToArray();
                owner.Calls.Add(new(CommandText, values, DbTransaction));
                return values;
            }
            public override int ExecuteNonQuery()
            {
                Record(); owner.Steps.Add("role"); return 0;
            }
            protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior)
            {
                var values = Record();
                owner.Steps.Add(CommandText.Contains("acquire_plugin") ? "acquire" : "release:" + values[2]);
                var row = owner.results.Dequeue();
                var table = new DataTable();
                for (int i = 0; i < (row?.Length ?? 4); i++) table.Columns.Add("column" + i, typeof(object));
                if (row is not null) table.Rows.Add(row);
                return table.CreateDataReader();
            }
        }

        internal sealed class Transaction(Connection owner, IsolationLevel isolation) : DbTransaction
        {
            public override IsolationLevel IsolationLevel => isolation;
            protected override DbConnection DbConnection => owner;
            public override void Commit() { owner.Commits++; owner.Steps.Add("commit"); owner.ActiveTransaction = null; }
            public override void Rollback() { owner.Rollbacks++; owner.Steps.Add("rollback"); owner.ActiveTransaction = null; }
            protected override void Dispose(bool disposing) { if (ReferenceEquals(owner.ActiveTransaction, this)) owner.ActiveTransaction = null; base.Dispose(disposing); }
        }
    }
}
