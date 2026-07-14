using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation.AspNetCore;
using PolyAuth.Firebase;
using PolyAuth.OAuth;

namespace PolyAuth;

/// <summary>The consumer entry point: <c>AddPolyAuth</c>.</summary>
public static class PolyAuthServiceCollectionExtensions
{
    public const string ConfigurationSectionName = "PolyAuth";

    /// <summary>
    /// Binds options from configuration (section <c>PolyAuth</c>), applies the configure delegate, then wires
    /// authentication, authorization, OpenIddict (Core+Server+Validation), the Firebase token-exchange grant,
    /// and the baseline MCP-client handlers — only for the providers whose <c>Enabled</c> is true.
    /// </summary>
    public static IServiceCollection AddPolyAuth(
        this IServiceCollection services,
        IConfiguration config,
        Action<PolyAuthOptions>? configure = null)
    {
        var environmentName = config[HostDefaults.EnvironmentKey]
            ?? Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")
            ?? Environments.Production;
        var isDevelopment = string.Equals(environmentName, Environments.Development, StringComparison.OrdinalIgnoreCase);

        var options = new PolyAuthOptions();
        config.GetSection(ConfigurationSectionName).Bind(options);
        configure?.Invoke(options);

        PolyAuthConfigValidation.Validate(options, isDevelopment);

        // Make the resolved options available to handlers/services.
        services.AddSingleton(Options.Create(options));
        services.TryAddSingleton<IPolyAuthPrincipalEnricher, NoOpPrincipalEnricher>();

        ConfigureFirebase(services, options);
        ConfigureOpenIddict(services, options, isDevelopment);
        ConfigureAuthentication(services, options);
        ConfigureAuthorization(services, options);

        return services;
    }

    private static void ConfigureFirebase(IServiceCollection services, PolyAuthOptions options)
    {
        // The token-exchange grant is gated on Firebase.Enabled too, so nothing needs these
        // services when Firebase login is off.
        if (!options.Firebase.Enabled)
        {
            return;
        }

        // The token verifier and the user provisioner are useful whenever Firebase login or the
        // token-exchange grant is in play.
        services.TryAddSingleton<IFirebaseTokenVerifier, FirebaseTokenVerifier>();
        services.TryAddSingleton<IFirebaseUserAdmin, FirebaseUserAdmin>();
        services.TryAddSingleton<IAuthTestUserProvisioner, AuthTestUserProvisioner>();
    }

    private static void ConfigureOpenIddict(IServiceCollection services, PolyAuthOptions options, bool isDevelopment)
    {
        if (!options.OAuth.Enabled)
        {
            return;
        }

        var oauth = options.OAuth;

        services.AddMemoryCache();
        services.AddScoped<IOAuthClientMetadataService, OAuthClientMetadataService>();
        services.AddHttpClient(OAuthClientMetadataService.HttpClientName, client => client.Timeout = TimeSpan.FromSeconds(3))
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });

        services.AddScoped<IOpenIddictSeeder, OpenIddictSeeder>();
        services.AddHostedService<OpenIddictSeederHostedService>();

        var publicResourceIndicators = OAuthResourceIndicators.GetPublicResourceIndicators(oauth, options.Mcp);

        var openIddict = services.AddOpenIddict();

        // Store provider: Mongo (the 0.1.x default, byte-for-byte) or SqlServer (an internal,
        // OpenIddict-only EF Core context — runtime row-mapping only; the consumer owns the DDL).
        // Validate() already rejects any other provider before we get here; the else is a defensive guard.
        if (StoreProviders.IsMongo(oauth.Store.Provider))
        {
            var mongoClient = new MongoClient(oauth.Store.ConnectionString);
            var database = mongoClient.GetDatabase(oauth.Store.DatabaseName);
            services.TryAddSingleton<IMongoClient>(mongoClient);
            services.TryAddSingleton(database);

            openIddict.AddCore(core => core.UseMongoDb().UseDatabase(database));
        }
        else if (StoreProviders.IsSqlServer(oauth.Store.Provider))
        {
            services.AddDbContext<PolyAuthSqlDbContext>(db =>
                db.UseSqlServer(oauth.Store.ConnectionString).UseOpenIddict());

            openIddict.AddCore(core => core.UseEntityFrameworkCore().UseDbContext<PolyAuthSqlDbContext>());
        }
        else
        {
            throw new InvalidOperationException(StoreProviders.UnsupportedMessage(oauth.Store.Provider));
        }

        openIddict
            .AddServer(server =>
            {
                if (!string.IsNullOrWhiteSpace(oauth.Issuer))
                {
                    server.SetIssuer(new Uri(oauth.Issuer.TrimEnd('/')));
                }

                server.SetAuthorizationEndpointUris("/connect/authorize")
                    .SetTokenEndpointUris("/connect/token")
                    .SetRevocationEndpointUris("/connect/revocation")
                    .SetEndSessionEndpointUris("/connect/logout");

                server.AllowAuthorizationCodeFlow()
                    .AllowRefreshTokenFlow()
                    .AllowClientCredentialsFlow()
                    .RequireProofKeyForCodeExchange();

                if (options.Firebase.Enabled)
                {
                    server.AllowCustomFlow(PolyAuthConstants.FirebaseTokenExchangeGrantType);
                }

                server.RegisterScopes(
                [
                    OpenIddictConstants.Scopes.OpenId,
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.OfflineAccess,
                    .. AuthScopes.Grantable,
                    .. oauth.Scopes.Additional
                ]);
                server.RegisterResources(publicResourceIndicators);

                // Grants (the Firebase token exchange only participates when Firebase login is on)
                if (options.Firebase.Enabled)
                {
                    server.AddEventHandler<OpenIddictServerEvents.HandleTokenRequestContext>(b =>
                        b.UseScopedHandler<FirebaseTokenExchangeHandler>());
                }

                server.AddEventHandler<OpenIddictServerEvents.HandleTokenRequestContext>(b =>
                    b.UseScopedHandler<ClientCredentialsTokenHandler>());

                // Baseline MCP-client handlers
                if (oauth.EnableUrlClientMetadata)
                {
                    server.AddEventHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>(b =>
                        b.UseScopedHandler<OAuthClientMetadataAuthorizationHandler>()
                            .SetOrder(OpenIddictServerHandlers.Authentication.ValidateClientIdParameter.Descriptor.Order + 500));
                    server.AddEventHandler<OpenIddictServerEvents.HandleConfigurationRequestContext>(b =>
                        b.UseScopedHandler<OAuthClientMetadataConfigurationHandler>()
                            .SetOrder(OpenIddictServerHandlers.Discovery.AttachAdditionalMetadata.Descriptor.Order + 1));
                }

                if (oauth.EnableLoopbackRedirects)
                {
                    server.AddEventHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>(b =>
                        b.UseScopedHandler<OAuthLoopbackRedirectAuthorizationHandler>()
                            .SetOrder(OpenIddictServerHandlers.Authentication.ValidateClientRedirectUri.Descriptor.Order - 100));
                }

                // Optional extensions
                if (oauth.EnableClientAssertion)
                {
                    server.AddEventHandler<OpenIddictServerEvents.ValidateTokenContext>(b =>
                        b.UseScopedHandler<OAuthClientAssertionTokenTypeHandler>()
                            .SetOrder(OpenIddictServerHandlers.Protection.ResolveTokenValidationParameters.Descriptor.Order + 500));
                    server.AddEventHandler<OpenIddictServerEvents.ProcessAuthenticationContext>(b =>
                        b.UseScopedHandler<OAuthClientAssertionAudienceCompatibilityHandler>()
                            .SetOrder(OpenIddictServerHandlers.ValidateClientAssertionAudience.Descriptor.Order - 100));
                }

                if (oauth.EnableDiagnostics)
                {
                    server.AddEventHandler<OpenIddictServerEvents.ApplyTokenResponseContext>(b =>
                        b.UseScopedHandler<OAuthTokenEndpointDiagnosticsHandler>());
                }

                server.SetAccessTokenLifetime(TimeSpan.FromMinutes(Math.Max(1, oauth.AccessTokenLifetimeMinutes)));
                server.SetRefreshTokenLifetime(TimeSpan.FromDays(Math.Max(1, oauth.RefreshTokenLifetimeDays)));

                ConfigureCertificates(server, oauth, isDevelopment);

                var aspNetCore = server.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough();

                if (isDevelopment)
                {
                    aspNetCore.DisableTransportSecurityRequirement();
                }
            })
            .AddValidation(validation =>
            {
                validation.UseLocalServer();
                validation.UseAspNetCore();
            });
    }

    private static void ConfigureCertificates(OpenIddictServerBuilder server, OAuthServerOptions oauth, bool isDevelopment)
    {
        if (oauth.SigningCertificate.IsConfigured)
        {
            server.AddSigningCertificate(CertificateLoader.Load(oauth.SigningCertificate, "PolyAuth:OAuth:SigningCertificate"));
        }
        else if (isDevelopment)
        {
            server.AddDevelopmentSigningCertificate();
        }

        if (oauth.EncryptionCertificate.IsConfigured)
        {
            server.AddEncryptionCertificate(CertificateLoader.Load(oauth.EncryptionCertificate, "PolyAuth:OAuth:EncryptionCertificate"));
        }
        else if (isDevelopment)
        {
            server.AddDevelopmentEncryptionCertificate();
        }
    }

    private static void ConfigureAuthentication(IServiceCollection services, PolyAuthOptions options)
    {
        if (!options.Firebase.Enabled && !options.OAuth.Enabled)
        {
            return;
        }

        var authBuilder = services.AddAuthentication(o =>
        {
            // Respect a default the consuming app already chose (e.g. its own JwtBearer registered
            // before AddPolyAuth): only claim the defaults when none exist yet. Apps where PolyAuth
            // is the sole authentication owner (the 0.1.x behavior) are unaffected.
            if (o.DefaultScheme is not null || o.DefaultAuthenticateScheme is not null)
            {
                return;
            }

            if (options.OAuth.Enabled)
            {
                o.DefaultAuthenticateScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
            }
            else
            {
                o.DefaultAuthenticateScheme = AuthSchemes.Firebase;
                o.DefaultChallengeScheme = AuthSchemes.Firebase;
            }
        });

        if (options.Firebase.Enabled)
        {
            authBuilder.AddScheme<AuthenticationSchemeOptions, FirebaseAuthenticationHandler>(AuthSchemes.Firebase, _ => { });
        }

        if (options.OAuth.Enabled)
        {
            authBuilder.AddCookie(AuthSchemes.OAuthSession, cookie =>
            {
                cookie.Cookie.Name = "__Host-polyauth-oauth";
                cookie.Cookie.HttpOnly = true;
                cookie.Cookie.Path = "/";
                cookie.Cookie.SameSite = SameSiteMode.Lax;
                cookie.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                cookie.ExpireTimeSpan = TimeSpan.FromMinutes(30);
                cookie.SlidingExpiration = false;
            });
        }
    }

    private static void ConfigureAuthorization(IServiceCollection services, PolyAuthOptions options)
    {
        if (!options.Firebase.Enabled && !options.OAuth.Enabled)
        {
            return;
        }

        services.AddAuthorization(o =>
        {
            if (options.OAuth.Enabled)
            {
                o.DefaultPolicy = ScopePolicy(AuthScopes.ApiRead, AuthScopes.ApiWrite);
                o.AddPolicy(AuthPolicies.ApiRead, ScopePolicy(AuthScopes.ApiRead, AuthScopes.ApiWrite));
                o.AddPolicy(AuthPolicies.ApiWrite, ScopePolicy(AuthScopes.ApiWrite));
                o.AddPolicy(AuthPolicies.McpRead, ScopePolicy(AuthScopes.McpRead, AuthScopes.McpWrite));
                o.AddPolicy(AuthPolicies.McpWrite, ScopePolicy(AuthScopes.McpWrite));
            }
            else if (options.Firebase.Enabled)
            {
                // Firebase-only: the API is protected by the Firebase ID-token scheme (no scope claim).
                o.DefaultPolicy = FirebasePolicy();
                o.AddPolicy(AuthPolicies.ApiRead, FirebasePolicy());
                o.AddPolicy(AuthPolicies.ApiWrite, FirebasePolicy());
            }

            if (options.Firebase.Enabled)
            {
                o.AddPolicy(AuthPolicies.FirebaseUser, FirebasePolicy());
            }
        });
    }

    private static AuthorizationPolicy ScopePolicy(params string[] scopes)
    {
        var builder = new AuthorizationPolicyBuilder(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        builder.RequireAuthenticatedUser();
        builder.RequireAssertion(context => ScopeAuthorization.HasAnyScope(context.User, scopes));
        return builder.Build();
    }

    private static AuthorizationPolicy FirebasePolicy()
    {
        var builder = new AuthorizationPolicyBuilder(AuthSchemes.Firebase);
        builder.RequireAuthenticatedUser();
        return builder.Build();
    }
}
