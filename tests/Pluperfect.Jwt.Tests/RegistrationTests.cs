using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using Shouldly;

namespace Pluperfect.Jwt.Tests;

[TestFixture]
public sealed class RegistrationTests
{
    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)))
            .Build();

    private static ServiceProvider Build(
        IConfiguration configuration,
        bool allowDevelopmentKey = false,
        bool secureOrigin = true)
    {
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddPluperfectJwt(configuration, allowDevelopmentKey, secureOrigin);
        return services.BuildServiceProvider();
    }

    [Test]
    public void Fails_without_a_signing_key_when_the_caller_permits_no_development_key()
    {
        // Fails closed. The default on allowDevelopmentKey is false, so forgetting it is safe.
        var provider = Build(Config(("Jwt:Issuer", "example.com")));

        Should.Throw<InvalidOperationException>(() => provider.GetRequiredService<JwtIssuer>());
    }

    [Test]
    public void Substitutes_a_derived_key_only_when_the_caller_permits_one()
    {
        var provider = Build(Config(("Jwt:Issuer", "example.com")), allowDevelopmentKey: true);

        Should.NotThrow(() => provider.GetRequiredService<JwtIssuer>());
    }

    [Test]
    public void Derives_a_different_development_key_for_each_issuer()
    {
        // Two services running side by side in development must not accept each other's tokens,
        // and this library must ship no key that every consumer would share.
        var a = Build(Config(("Jwt:Issuer", "pokestory.net")), allowDevelopmentKey: true)
            .GetRequiredService<IOptions<PluperfectJwtOptions>>().Value.SigningKey;

        var b = Build(Config(("Jwt:Issuer", "forty.life")), allowDevelopmentKey: true)
            .GetRequiredService<IOptions<PluperfectJwtOptions>>().Value.SigningKey;

        a.ShouldNotBeNullOrWhiteSpace();
        a.ShouldNotBe(b);
    }

    [Test]
    public void Derives_the_same_development_key_across_restarts()
    {
        // Derived rather than random, so restarting during development does not sign a developer
        // out mid-task.
        var first = Build(Config(("Jwt:Issuer", "example.com")), allowDevelopmentKey: true)
            .GetRequiredService<IOptions<PluperfectJwtOptions>>().Value.SigningKey;

        var second = Build(Config(("Jwt:Issuer", "example.com")), allowDevelopmentKey: true)
            .GetRequiredService<IOptions<PluperfectJwtOptions>>().Value.SigningKey;

        first.ShouldBe(second);
    }

    [Test]
    public void Leaves_a_configured_key_alone_even_where_a_development_key_is_permitted()
    {
        const string configured = "a-real-configured-key-of-sufficient-length";

        var key = Build(
                Config(("Jwt:Issuer", "example.com"), ("Jwt:SigningKey", configured)),
                allowDevelopmentKey: true)
            .GetRequiredService<IOptions<PluperfectJwtOptions>>().Value.SigningKey;

        key.ShouldBe(configured);
    }

    [Test]
    public void Registers_no_refresh_token_store()
    {
        // Deliberate: that needs a database, and every consumer already has one this library
        // should not choose for them.
        var provider = Build(
            Config(("Jwt:Issuer", "example.com"), ("Jwt:SigningKey", "a-real-configured-key-of-sufficient-length")));

        provider.GetService<IRefreshTokenStore>().ShouldBeNull();
    }

    private sealed class NullLoggerProvider : ILoggerProvider
    {
        public static readonly NullLoggerProvider Instance = new();

        public ILogger CreateLogger(string categoryName) => Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;

        public void Dispose()
        {
        }
    }
}
