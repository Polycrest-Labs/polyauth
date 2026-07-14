using Xunit;

namespace PolyAuth.Tests;

/// <summary>
/// The session-bridge gating matrix (Firebase on/off × SessionBridge set/unset) and its fail-fast
/// validation. Defaults must preserve 0.1.x behavior: the bridge follows Firebase.Enabled and
/// authenticates with the Firebase scheme unless the consumer configures otherwise.
/// </summary>
public sealed class SessionBridgeOptionsTests
{
    private static PolyAuthOptions Options(Action<PolyAuthOptions>? configure = null)
    {
        var options = new PolyAuthOptions();
        options.OAuth.Enabled = true;
        options.OAuth.Store.ConnectionString = "mongodb://localhost:27017";
        options.OAuth.Store.DatabaseName = "db";
        configure?.Invoke(options);
        return options;
    }

    [Fact]
    public void Default_follows_firebase_enabled()
    {
        Assert.True(SessionBridgeGating.IsEnabled(Options(o => o.Firebase.Enabled = true)));
        Assert.False(SessionBridgeGating.IsEnabled(Options(o => o.Firebase.Enabled = false)));
    }

    [Fact]
    public void Explicit_enabled_overrides_firebase()
    {
        Assert.True(SessionBridgeGating.IsEnabled(Options(o =>
        {
            o.Firebase.Enabled = false;
            o.OAuth.SessionBridge.Enabled = true;
        })));

        Assert.False(SessionBridgeGating.IsEnabled(Options(o =>
        {
            o.Firebase.Enabled = true;
            o.OAuth.SessionBridge.Enabled = false;
        })));
    }

    [Fact]
    public void Schemes_default_to_firebase()
    {
        Assert.Equal([AuthSchemes.Firebase], SessionBridgeGating.ResolveSchemes(Options(o => o.Firebase.Enabled = true)));
        Assert.Equal([AuthSchemes.Firebase], SessionBridgeGating.ResolveSchemes(Options(o => o.OAuth.SessionBridge.AuthenticationSchemes = [])));
    }

    [Fact]
    public void Configured_schemes_win()
    {
        var options = Options(o =>
        {
            o.Firebase.Enabled = true;
            o.OAuth.SessionBridge.AuthenticationSchemes = ["Bearer", "OtherBearer"];
        });

        Assert.Equal(["Bearer", "OtherBearer"], SessionBridgeGating.ResolveSchemes(options));
    }

    [Fact]
    public void Configured_schemes_imply_enabled_without_firebase()
    {
        // A BYO-identity consumer that sets only the schemes (Firebase off, Enabled left null) still gets
        // the endpoint mapped — no need to also set Enabled = true.
        Assert.True(SessionBridgeGating.IsEnabled(Options(o =>
        {
            o.Firebase.Enabled = false;
            o.OAuth.SessionBridge.AuthenticationSchemes = ["Bearer"];
        })));

        // Explicit Enabled = false still wins over configured schemes.
        Assert.False(SessionBridgeGating.IsEnabled(Options(o =>
        {
            o.Firebase.Enabled = false;
            o.OAuth.SessionBridge.Enabled = false;
            o.OAuth.SessionBridge.AuthenticationSchemes = ["Bearer"];
        })));
    }

    [Fact]
    public void Enabled_without_schemes_and_without_firebase_fails_validation()
    {
        var options = Options(o =>
        {
            o.Firebase.Enabled = false;
            o.OAuth.SessionBridge.Enabled = true;
        });

        var ex = Assert.Throws<InvalidOperationException>(() => PolyAuthConfigValidation.Validate(options, isDevelopment: true));
        Assert.Contains("SessionBridge", ex.Message);
        Assert.Contains("AuthenticationSchemes", ex.Message);
    }

    [Fact]
    public void Enabled_with_schemes_passes_validation_without_firebase()
    {
        var options = Options(o =>
        {
            o.Firebase.Enabled = false;
            o.OAuth.SessionBridge.Enabled = true;
            o.OAuth.SessionBridge.AuthenticationSchemes = ["Bearer"];
        });

        PolyAuthConfigValidation.Validate(options, isDevelopment: true);
    }

    [Fact]
    public void Enabled_without_schemes_with_firebase_passes_validation()
    {
        var options = Options(o =>
        {
            o.Firebase.Enabled = true;
            o.OAuth.SessionBridge.Enabled = true;
        });

        PolyAuthConfigValidation.Validate(options, isDevelopment: true);
    }
}
