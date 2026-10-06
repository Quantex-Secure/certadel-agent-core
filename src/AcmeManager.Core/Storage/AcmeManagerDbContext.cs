using AcmeManager.Core.Storage.Entities;

using Microsoft.EntityFrameworkCore;

namespace AcmeManager.Core.Storage;

public sealed class AcmeManagerDbContext(DbContextOptions<AcmeManagerDbContext> options) : DbContext(options)
{
    public DbSet<Account> Accounts => Set<Account>();

    public DbSet<Renewal> Renewals => Set<Renewal>();

    public DbSet<Certificate> Certificates => Set<Certificate>();

    public DbSet<HistoryEntry> History => Set<HistoryEntry>();

    public DbSet<Secret> Secrets => Set<Secret>();

    public DbSet<SettingsValue> Settings => Set<SettingsValue>();

    public DbSet<DnsProvider> DnsProviders => Set<DnsProvider>();

    protected override void OnModelCreating(ModelBuilder mb)
    {
        mb.Entity<Account>().HasIndex(a => a.Name).IsUnique();

        mb.Entity<Renewal>().HasIndex(r => r.Name).IsUnique();
        mb.Entity<Renewal>()
            .HasOne(r => r.Account)
            .WithMany()
            .HasForeignKey(r => r.AccountId)
            .OnDelete(DeleteBehavior.Restrict);

        mb.Entity<Certificate>()
            .HasOne(c => c.Renewal)
            .WithMany()
            .HasForeignKey(c => c.RenewalId)
            .OnDelete(DeleteBehavior.Cascade);
        mb.Entity<Certificate>().HasIndex(c => c.Thumbprint);

        mb.Entity<HistoryEntry>()
            .HasOne(h => h.Renewal)
            .WithMany()
            .HasForeignKey(h => h.RenewalId)
            .OnDelete(DeleteBehavior.SetNull);
        mb.Entity<HistoryEntry>().HasIndex(h => h.At);

        mb.Entity<Secret>().HasIndex(s => s.Name).IsUnique();

        mb.Entity<SettingsValue>().HasKey(s => s.Key);

        mb.Entity<DnsProvider>().HasIndex(p => p.Name).IsUnique();
    }
}