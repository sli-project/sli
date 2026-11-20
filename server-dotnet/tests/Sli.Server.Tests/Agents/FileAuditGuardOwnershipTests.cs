using System.Reflection;
using Sli.Server.Agents.FileAudit;
using Xunit;
namespace Sli.Server.Tests.Agents;
public class FileAuditGuardOwnershipTests
{
    private sealed class Guard:IDisposable { public bool Disposed;public void Dispose()=>Disposed=true; }
    [Fact]
    public void PostLockThrowDisposesBeforePropagating()
    {
        var type=typeof(FileAuditResult).Assembly.GetType("Sli.Server.Agents.FileAudit.FileAuditHookAdmission")!;
        var method=type.GetMethod("TransferAfterValidation",BindingFlags.Static|BindingFlags.NonPublic)!;
        var guard=new Guard();var error=Assert.Throws<TargetInvocationException>(()=>method.Invoke(null,[guard,(Func<bool>)(()=>throw new InvalidDataException("synthetic"))]));
        Assert.IsType<InvalidDataException>(error.InnerException);Assert.True(guard.Disposed);
        var absent=new Guard();Assert.Throws<TargetInvocationException>(()=>method.Invoke(null,[absent,(Func<bool>)(()=>false)]));Assert.True(absent.Disposed);
        var valid=new Guard();Assert.Same(valid,method.Invoke(null,[valid,(Func<bool>)(()=>true)]));Assert.False(valid.Disposed);valid.Dispose();
    }
}

