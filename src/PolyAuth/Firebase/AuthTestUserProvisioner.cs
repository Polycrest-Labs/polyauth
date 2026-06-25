using FirebaseAdmin.Auth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace PolyAuth
{
    /// <summary>A persistent end-to-end test user.</summary>
    public sealed record TestUser(string Uid, string Email);

    /// <summary>
    /// Provisions a persistent E2E test user. <b>Get-or-create only</b>: the password is set only on
    /// creation and never reset on subsequent calls (resetting revokes refresh tokens and logs
    /// existing sessions out).
    /// </summary>
    public interface IAuthTestUserProvisioner
    {
        Task<TestUser> EnsureTestUserAsync(string email, string password, CancellationToken ct = default);
    }
}

namespace PolyAuth.Firebase
{
    /// <summary>The minimal Firebase user-admin surface the provisioner needs (so it can be faked in tests).</summary>
    public interface IFirebaseUserAdmin
    {
        Task<TestUser?> FindByEmailAsync(string email, CancellationToken ct);
        Task<TestUser> CreateAsync(string email, string password, CancellationToken ct);
    }

    /// <summary>The production user-admin backed by the Firebase Admin SDK.</summary>
    public sealed class FirebaseUserAdmin : IFirebaseUserAdmin
    {
        private readonly Lazy<FirebaseAuth> _auth;

        public FirebaseUserAdmin(IOptions<PolyAuthOptions> options)
        {
            var firebase = options.Value.Firebase;
            _auth = new Lazy<FirebaseAuth>(() => FirebaseAuth.GetAuth(FirebaseAppFactory.GetOrCreate(firebase)));
        }

        public async Task<TestUser?> FindByEmailAsync(string email, CancellationToken ct)
        {
            try
            {
                var user = await _auth.Value.GetUserByEmailAsync(email, ct);
                return new TestUser(user.Uid, user.Email ?? email);
            }
            catch (FirebaseAuthException ex) when (ex.AuthErrorCode == AuthErrorCode.UserNotFound)
            {
                return null;
            }
        }

        public async Task<TestUser> CreateAsync(string email, string password, CancellationToken ct)
        {
            var created = await _auth.Value.CreateUserAsync(new UserRecordArgs
            {
                Email = email,
                Password = password,
                EmailVerified = true
            }, ct);
            return new TestUser(created.Uid, created.Email ?? email);
        }
    }

    /// <summary>Get-or-create implementation. Never touches the password of an existing user.</summary>
    public sealed class AuthTestUserProvisioner : IAuthTestUserProvisioner
    {
        private readonly IFirebaseUserAdmin _admin;
        private readonly ILogger<AuthTestUserProvisioner> _logger;

        public AuthTestUserProvisioner(IFirebaseUserAdmin admin, ILogger<AuthTestUserProvisioner> logger)
        {
            _admin = admin;
            _logger = logger;
        }

        public async Task<TestUser> EnsureTestUserAsync(string email, string password, CancellationToken ct = default)
        {
            var existing = await _admin.FindByEmailAsync(email, ct);
            if (existing is not null)
            {
                _logger.LogInformation("Reusing existing test user {Email} ({Uid}); password left unchanged", email, existing.Uid);
                return existing;
            }

            var created = await _admin.CreateAsync(email, password, ct);
            _logger.LogInformation("Created test user {Email} ({Uid})", email, created.Uid);
            return created;
        }
    }
}
