using System.Runtime.InteropServices;

namespace Sli.Server.Hosting;

internal static class WorkerShutdown
{
    internal static async Task<int> RunAsync(Func<CancellationToken, Task<int>> run, CancellationToken invocation = default)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(invocation);

        void RequestStop()
        {
            try { stop.Cancel(); }
            catch (ObjectDisposedException) { /* A dispatched signal may arrive after the worker has exited. */ }
        }

        void OnSignal(PosixSignalContext context)
        {
            context.Cancel = true;
            RequestStop();
        }

        bool linux = OperatingSystem.IsLinux();
        using var term = linux ? PosixSignalRegistration.Create(PosixSignal.SIGTERM, OnSignal) : null;
        using var interrupt = linux ? PosixSignalRegistration.Create(PosixSignal.SIGINT, OnSignal) : null;
        ConsoleCancelEventHandler onCancel = (_, e) => { e.Cancel = true; RequestStop(); };
        if (!linux) Console.CancelKeyPress += onCancel;
        try { return await run(stop.Token); }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { return 0; }
        finally { if (!linux) Console.CancelKeyPress -= onCancel; }
    }
}
