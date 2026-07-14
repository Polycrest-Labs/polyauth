using Microsoft.EntityFrameworkCore;

namespace PolyAuth.OAuth;

/// <summary>
/// The internal, OpenIddict-only EF Core context backing the <c>SqlServer</c> store provider. It owns no
/// entities of its own — the model comes entirely from <c>UseOpenIddict()</c> on the options builder at
/// registration time. EF is a runtime row-mapper here, never a schema authority: consuming apps create the
/// four OpenIddict tables with their own migration tooling (e.g. a DbUp script generated once from
/// <c>Database.GenerateCreateScript()</c>).
/// </summary>
internal sealed class PolyAuthSqlDbContext : DbContext
{
    public PolyAuthSqlDbContext(DbContextOptions<PolyAuthSqlDbContext> options)
        : base(options)
    {
    }
}
