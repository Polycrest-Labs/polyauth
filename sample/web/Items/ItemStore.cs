using System.Collections.Concurrent;
using Microsoft.Azure.Cosmos;

namespace Sample.Web.Items;

/// <summary>A user-owned item. Partition key is the owner id.</summary>
public sealed record Item(string Id, string OwnerId, string Title, DateTimeOffset CreatedAt);

public sealed record CreateItemRequest(string Title);

public interface IItemStore
{
    Task<IReadOnlyList<Item>> ListAsync(string ownerId, CancellationToken ct = default);
    Task<Item> CreateAsync(string ownerId, string title, CancellationToken ct = default);
    Task<bool> DeleteAsync(string ownerId, string id, CancellationToken ct = default);
}

/// <summary>In-memory store used for local dev and tests (no Cosmos dependency).</summary>
public sealed class InMemoryItemStore : IItemStore
{
    private readonly ConcurrentDictionary<string, Item> _items = new();

    public Task<IReadOnlyList<Item>> ListAsync(string ownerId, CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<Item>>(
            _items.Values.Where(i => i.OwnerId == ownerId).OrderByDescending(i => i.CreatedAt).ToList());

    public Task<Item> CreateAsync(string ownerId, string title, CancellationToken ct = default)
    {
        var item = new Item(Guid.NewGuid().ToString("N"), ownerId, title, DateTimeOffset.UtcNow);
        _items[item.Id] = item;
        return Task.FromResult(item);
    }

    public Task<bool> DeleteAsync(string ownerId, string id, CancellationToken ct = default)
    {
        if (_items.TryGetValue(id, out var existing) && existing.OwnerId == ownerId)
        {
            return Task.FromResult(_items.TryRemove(id, out _));
        }

        return Task.FromResult(false);
    }
}

/// <summary>Cosmos DB (SQL) serverless-backed store. Used when CosmosDb:ConnectionString is configured.</summary>
public sealed class CosmosItemStore : IItemStore
{
    private const string ContainerId = "items";
    private readonly Container _container;

    public CosmosItemStore(CosmosClient client, string databaseId)
        => _container = client.GetContainer(databaseId, ContainerId);

    public async Task<IReadOnlyList<Item>> ListAsync(string ownerId, CancellationToken ct = default)
    {
        var query = new QueryDefinition("SELECT * FROM c WHERE c.ownerId = @owner ORDER BY c.createdAt DESC")
            .WithParameter("@owner", ownerId);
        var iterator = _container.GetItemQueryIterator<Item>(
            query, requestOptions: new QueryRequestOptions { PartitionKey = new PartitionKey(ownerId) });

        var results = new List<Item>();
        while (iterator.HasMoreResults)
        {
            foreach (var item in await iterator.ReadNextAsync(ct))
            {
                results.Add(item);
            }
        }

        return results;
    }

    public async Task<Item> CreateAsync(string ownerId, string title, CancellationToken ct = default)
    {
        var item = new Item(Guid.NewGuid().ToString("N"), ownerId, title, DateTimeOffset.UtcNow);
        await _container.CreateItemAsync(item, new PartitionKey(ownerId), cancellationToken: ct);
        return item;
    }

    public async Task<bool> DeleteAsync(string ownerId, string id, CancellationToken ct = default)
    {
        try
        {
            await _container.DeleteItemAsync<Item>(id, new PartitionKey(ownerId), cancellationToken: ct);
            return true;
        }
        catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return false;
        }
    }

    public static async Task EnsureContainerAsync(CosmosClient client, string databaseId, CancellationToken ct = default)
    {
        var db = await client.CreateDatabaseIfNotExistsAsync(databaseId, cancellationToken: ct);
        await db.Database.CreateContainerIfNotExistsAsync(ContainerId, "/ownerId", cancellationToken: ct);
    }
}
