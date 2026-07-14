using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using PolyAuth.OAuth;
using Xunit;
using Xunit.Abstractions;

namespace PolyAuth.IntegrationTests;

/// <summary>
/// Exercises the SqlServer store provider (OpenIddict.EntityFrameworkCore over the internal
/// <see cref="PolyAuthSqlDbContext"/>): schema creation, CRUD through the OpenIddict managers, and
/// restart persistence across a fresh provider. Runs only when POLYAUTH_TEST_SQLSERVER is set (a SQL
/// Server connection string, e.g. <c>Server=localhost\SQLEXPRESS;Database=PolyAuthTest;Integrated
/// Security=true;TrustServerCertificate=true</c>) — the test swaps in its own unique scratch database
/// name and drops it afterwards, so CI without SQL Server simply reports it as inconclusive.
/// </summary>
[Trait("category", "sqlserver")]
public sealed class SqlServerStoreTests
{
    private readonly ITestOutputHelper _output;
    private static readonly string? SqlConnectionString = Environment.GetEnvironmentVariable("POLYAUTH_TEST_SQLSERVER");

    public SqlServerStoreTests(ITestOutputHelper output) => _output = output;

    private static ServiceProvider BuildProvider(string connectionString)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<PolyAuthSqlDbContext>(db => db.UseSqlServer(connectionString).UseOpenIddict());
        services.AddOpenIddict().AddCore(core => core.UseEntityFrameworkCore().UseDbContext<PolyAuthSqlDbContext>());
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task OpenIddict_store_crud_and_persistence_on_sql_server()
    {
        if (string.IsNullOrWhiteSpace(SqlConnectionString))
        {
            _output.WriteLine("POLYAUTH_TEST_SQLSERVER not set — skipping the SQL Server store test.");
            return;
        }

        // A unique scratch database per run, dropped in the finally.
        var builder = new SqlConnectionStringBuilder(SqlConnectionString)
        {
            InitialCatalog = "PolyAuthSqlTest_" + Guid.NewGuid().ToString("N")[..8]
        };
        var connectionString = builder.ConnectionString;

        try
        {
            // 1) Schema creation — EnsureCreated builds the four OpenIddict tables from UseOpenIddict().
            await using (var provider = BuildProvider(connectionString))
            using (var scope = provider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<PolyAuthSqlDbContext>();
                await context.Database.EnsureCreatedAsync();
                _output.WriteLine($"Created scratch database {builder.InitialCatalog} with the OpenIddict schema.");
            }

            // 2) CRUD through the OpenIddict managers (application + scope).
            await using (var provider = BuildProvider(connectionString))
            using (var scope = provider.CreateScope())
            {
                var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "sql-test-client",
                    DisplayName = "SQL test client",
                    ClientType = OpenIddictConstants.ClientTypes.Public,
                    Permissions = { OpenIddictConstants.Permissions.Endpoints.Token }
                });
                Assert.NotNull(await appManager.FindByClientIdAsync("sql-test-client"));

                var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
                await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = "sql.test",
                    DisplayName = "SQL test scope"
                });
                Assert.NotNull(await scopeManager.FindByNameAsync("sql.test"));
                _output.WriteLine("Created and read back an application and a scope through the managers.");
            }

            // 3) Restart persistence — a fresh provider/context must still see the rows, then delete them.
            await using (var provider = BuildProvider(connectionString))
            using (var scope = provider.CreateScope())
            {
                var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                var found = await appManager.FindByClientIdAsync("sql-test-client");
                Assert.NotNull(found);
                await appManager.DeleteAsync(found!);
                Assert.Null(await appManager.FindByClientIdAsync("sql-test-client"));

                var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
                var foundScope = await scopeManager.FindByNameAsync("sql.test");
                Assert.NotNull(foundScope);
                await scopeManager.DeleteAsync(foundScope!);
                Assert.Null(await scopeManager.FindByNameAsync("sql.test"));
                _output.WriteLine("Rows persisted across a new provider and deleted cleanly (persistence OK).");
            }
        }
        finally
        {
            await using var provider = BuildProvider(connectionString);
            using var scope = provider.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<PolyAuthSqlDbContext>();
            await context.Database.EnsureDeletedAsync();
        }
    }
}
