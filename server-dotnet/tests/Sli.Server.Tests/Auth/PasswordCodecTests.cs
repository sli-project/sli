using System.Text.RegularExpressions;
using System.Text;
using Sli.Server.Auth.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class PasswordCodecTests
{
    [Theory]
    [InlineData("")]
    [InlineData("синтетический 🔐 e\u0301")]
    [InlineData("before\0after")]
    public void RoundTripUsesLegacyPhcAndExactUtf8(string password)
    {
        var codec = new PasswordCodec();
        string encoded = codec.Hash(password);
        Assert.StartsWith("$argon2id$v=19$m=65536,t=3,p=2$", encoded);
        Assert.True(codec.Verify(encoded, password).Valid);
        Assert.False(codec.Verify(encoded, password + "x").Valid);
        Assert.False(codec.NeedsRehash(encoded));
    }

    [Theory]
    [InlineData("")]
    [InlineData("plaintext")]
    [InlineData("$argon2id$v=20$m=8,t=1,p=1$YWJjZGVmZ2g$YWJjZGVmZ2g")]
    [InlineData("$argon2id$v=19$m=invalid,t=3,p=2$a$b")]
    [InlineData("$argon2id$v=19$m=1,t=1,p=2$c2FsdHNhbHQ$YWJjZA")]
    [InlineData("$argon2id$v=19$m=32,t=0,p=2$c2FsdHNhbHQ$YWJjZA")]
    public void InvalidHashesFailClosed(string encoded) => Assert.False(new PasswordCodec().Verify(encoded, "test").Valid);

    [Fact]
    public void InvalidUnicodeIsNotReplacedWithAnotherPassword()
    {
        var codec = new PasswordCodec();
        Assert.Throws<EncoderFallbackException>(() => codec.Hash("\ud800"));
        Assert.Throws<EncoderFallbackException>(() => codec.Verify("invalid", "\ud800"));
    }

    [Fact]
    public void SessionTokensMatchPythonUrlsafe32AndSha256()
    {
        var tokens = new CredentialTokens();
        string a = tokens.NewSessionToken(), b = tokens.NewSessionToken();
        Assert.Matches(new Regex("^[A-Za-z0-9_-]{43}$"), a);
        Assert.NotEqual(a, b);
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", tokens.Digest(""));
    }
}
