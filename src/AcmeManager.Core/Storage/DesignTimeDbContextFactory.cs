using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace AcmeManager.Core.Storage;

/// <summary>
/// Used by <c>dotnet ef migrations</c> tooling to instantiate the context
/// without booting the full application host. The SQLite path here is a
/// throwaway — only the schema is what gets baked into the migration.
/// </summary>
public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<AcmeManagerDbContext>
{
    public AcmeManagerDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<AcmeManagerDbContext>()
            .UseSqlite("Data Source=designtime.db")
            .Options;

        return new AcmeManagerDbContext(options);
    }
}