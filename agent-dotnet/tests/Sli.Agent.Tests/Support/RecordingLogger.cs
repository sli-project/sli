using Microsoft.Extensions.Logging;
using Sli.Agent.Service;

namespace Sli.Agent.Tests.Support;

internal sealed class RecordingLogger : ILogger<AgentWorker>
{
    private int _count;
    public TaskCompletionSource<(LogLevel Level, string Message, Exception? Exception)> Entry { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public TaskCompletionSource<(LogLevel Level, string Message, Exception? Exception)> SecondEntry { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        var entry = (logLevel, formatter(state, exception), exception);
        Entry.TrySetResult(entry);
        if (Interlocked.Increment(ref _count) == 2) SecondEntry.TrySetResult(entry);
    }
}
