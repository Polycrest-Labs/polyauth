using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolyAuth;

namespace Sample.Web.Items;

[ApiController]
[Route("api/items")]
public sealed class ItemsController : ControllerBase
{
    private readonly IItemStore _store;

    public ItemsController(IItemStore store) => _store = store;

    private string UserId =>
        User.FindFirstValue("sub")
        ?? User.FindFirstValue("uid")
        ?? User.FindFirstValue(ClaimTypes.NameIdentifier)
        ?? throw new InvalidOperationException("The authenticated principal is missing a subject claim.");

    [HttpGet]
    [Authorize(Policy = AuthPolicies.ApiRead)]
    [ProducesResponseType(typeof(IReadOnlyList<Item>), StatusCodes.Status200OK)]
    public async Task<IActionResult> List(CancellationToken ct)
        => Ok(await _store.ListAsync(UserId, ct));

    [HttpPost]
    [Authorize(Policy = AuthPolicies.ApiWrite)]
    [ProducesResponseType(typeof(Item), StatusCodes.Status200OK)]
    public async Task<IActionResult> Create([FromBody] CreateItemRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Title))
        {
            return BadRequest(new ProblemDetails { Title = "Title is required.", Status = StatusCodes.Status400BadRequest });
        }

        return Ok(await _store.CreateAsync(UserId, request.Title.Trim(), ct));
    }

    [HttpDelete("{id}")]
    [Authorize(Policy = AuthPolicies.ApiWrite)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Delete(string id, CancellationToken ct)
        => Ok(new { deleted = await _store.DeleteAsync(UserId, id, ct) });
}
