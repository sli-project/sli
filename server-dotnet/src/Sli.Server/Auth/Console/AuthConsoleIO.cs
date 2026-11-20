using System.Text;

namespace Sli.Server.Auth.Commands;

public interface IAuthConsoleIO
{
    TextWriter Output { get; }
    TextWriter Error { get; }
    bool CanPromptPassword { get; }
    bool IsOutputRedirected => Console.IsOutputRedirected;
    Task<string> ReadPasswordAsync(string prompt, CancellationToken ct);
}

public sealed class AuthConsoleIO : IAuthConsoleIO
{
    public TextWriter Output => Console.Out;
    public TextWriter Error => Console.Error;
    public bool CanPromptPassword => !Console.IsInputRedirected;

    public async Task<string> ReadPasswordAsync(string prompt, CancellationToken ct)
    {
        if (!CanPromptPassword) throw new InvalidOperationException("password_terminal_required");
        Error.Write(prompt);
        var value = new StringBuilder();
        try
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                if (!Console.KeyAvailable) { await Task.Delay(25, ct); continue; }
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter) { Error.WriteLine(); return value.ToString(); }
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (value.Length > 0) value.Length -= value.Length >= 2 && char.IsLowSurrogate(value[^1]) && char.IsHighSurrogate(value[^2]) ? 2 : 1;
                    continue;
                }
                if (key.KeyChar == '\u0003') throw new OperationCanceledException(ct);
                value.Append(key.KeyChar);
            }
        }
        finally { value.Clear(); }
    }
}
