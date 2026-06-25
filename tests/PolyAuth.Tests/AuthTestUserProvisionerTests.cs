using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using PolyAuth.Firebase;
using Xunit;

namespace PolyAuth.Tests;

public sealed class AuthTestUserProvisionerTests
{
    [Fact]
    public async Task Creates_user_when_missing()
    {
        var admin = new Mock<IFirebaseUserAdmin>();
        admin.Setup(a => a.FindByEmailAsync("e2e@test.dev", It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);
        admin.Setup(a => a.CreateAsync("e2e@test.dev", "pw", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TestUser("new-uid", "e2e@test.dev"));

        var provisioner = new AuthTestUserProvisioner(admin.Object, NullLogger<AuthTestUserProvisioner>.Instance);
        var user = await provisioner.EnsureTestUserAsync("e2e@test.dev", "pw");

        Assert.Equal("new-uid", user.Uid);
        admin.Verify(a => a.CreateAsync("e2e@test.dev", "pw", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Reuses_existing_user_and_never_resets_password()
    {
        var admin = new Mock<IFirebaseUserAdmin>();
        admin.Setup(a => a.FindByEmailAsync("e2e@test.dev", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TestUser("existing-uid", "e2e@test.dev"));

        var provisioner = new AuthTestUserProvisioner(admin.Object, NullLogger<AuthTestUserProvisioner>.Instance);

        // Call twice — get-or-create must be idempotent.
        var first = await provisioner.EnsureTestUserAsync("e2e@test.dev", "new-password");
        var second = await provisioner.EnsureTestUserAsync("e2e@test.dev", "another-password");

        Assert.Equal("existing-uid", first.Uid);
        Assert.Equal("existing-uid", second.Uid);

        // The password is set only on creation; an existing user is never recreated/updated.
        admin.Verify(a => a.CreateAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
