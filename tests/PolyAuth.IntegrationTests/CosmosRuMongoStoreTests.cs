using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;
using OpenIddict.Abstractions;
using OpenIddict.MongoDb;
using OpenIddict.MongoDb.Models;
using Xunit;
using Xunit.Abstractions;

namespace PolyAuth.IntegrationTests;

/// <summary>
/// Exercises OpenIddict.MongoDb CRUD + index creation + restart-persistence against the live
/// Azure Cosmos DB for MongoDB (RU serverless) account. Runs only when POLYAUTH_COSMOS_MONGO is set
/// (the connection string), so CI without Azure simply reports it as inconclusive.
/// </summary>
[Trait("category", "ru")]
public sealed class CosmosRuMongoStoreTests
{
    private readonly ITestOutputHelper _output;
    private static readonly string? CosmosConnectionString = Environment.GetEnvironmentVariable("POLYAUTH_COSMOS_MONGO");

    public CosmosRuMongoStoreTests(ITestOutputHelper output) => _output = output;

    private ServiceProvider BuildProvider(IMongoDatabase database)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOpenIddict().AddCore(core => core.UseMongoDb().UseDatabase(database));
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task OpenIddict_store_crud_index_and_persistence_on_cosmos_ru()
    {
        if (string.IsNullOrWhiteSpace(CosmosConnectionString))
        {
            _output.WriteLine("POLYAUTH_COSMOS_MONGO not set — skipping the live Cosmos RU store test.");
            return;
        }

        var settings = MongoClientSettings.FromConnectionString(CosmosConnectionString);
        var client = new MongoClient(settings);
        var dbName = "polyauth-ru-test-" + Guid.NewGuid().ToString("N")[..8];
        var database = client.GetDatabase(dbName);

        try
        {
            // 1) Index creation (the indexes OpenIddict relies on) must succeed on RU serverless.
            var applications = database.GetCollection<OpenIddictMongoDbApplication>("applications");
            await applications.Indexes.CreateOneAsync(new CreateIndexModel<OpenIddictMongoDbApplication>(
                Builders<OpenIddictMongoDbApplication>.IndexKeys.Ascending(a => a.ClientId),
                new CreateIndexOptions { Unique = true }));
            _output.WriteLine("Created unique index on applications.client_id (RU OK).");

            var scopes = database.GetCollection<OpenIddictMongoDbScope>("scopes");
            await scopes.Indexes.CreateOneAsync(new CreateIndexModel<OpenIddictMongoDbScope>(
                Builders<OpenIddictMongoDbScope>.IndexKeys.Ascending(s => s.Name),
                new CreateIndexOptions { Unique = true }));

            // 2) CRUD through the OpenIddict managers.
            await using (var provider = BuildProvider(database))
            using (var scope = provider.CreateScope())
            {
                var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                await appManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "ru-test-client",
                    DisplayName = "RU test client",
                    ClientType = OpenIddictConstants.ClientTypes.Public,
                    Permissions = { OpenIddictConstants.Permissions.Endpoints.Token }
                });

                var found = await appManager.FindByClientIdAsync("ru-test-client");
                Assert.NotNull(found);
                _output.WriteLine("Created and read back an OpenIddict application on RU.");
            }

            // 3) Restart persistence — a fresh client/provider must still see the document.
            var client2 = new MongoClient(MongoClientSettings.FromConnectionString(CosmosConnectionString));
            var database2 = client2.GetDatabase(dbName);
            await using (var provider = BuildProvider(database2))
            using (var scope = provider.CreateScope())
            {
                var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                var found = await appManager.FindByClientIdAsync("ru-test-client");
                Assert.NotNull(found);
                _output.WriteLine("Application persisted across a new Mongo client connection (RU persistence OK).");

                await appManager.DeleteAsync(found!);
                Assert.Null(await appManager.FindByClientIdAsync("ru-test-client"));
            }
        }
        finally
        {
            await client.DropDatabaseAsync(dbName);
        }
    }
}
