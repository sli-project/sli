namespace Sli.Agent.Core;

/// <summary>Protects the agent's private key at rest. Windows uses DPAPI (machine scope); the default is a restricted file only.</summary>
public interface IKeyProtector
{
    /// <summary>Stored beside the key so a later reader knows how to open it (<c>dpapi_local_machine</c>, <c>restricted_file</c>).</summary>
    string Name { get; }

    byte[] Protect(byte[] data);

    byte[] Unprotect(byte[] data);
}

/// <summary>No encryption: the only barrier is the state directory's ACL. For tests and non-Windows hosts.</summary>
public sealed class RestrictedFileKeyProtector : IKeyProtector
{
    public string Name => "restricted_file";

    public byte[] Protect(byte[] data) => data;

    public byte[] Unprotect(byte[] data) => data;
}
