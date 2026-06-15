using CyberDetectionAI.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberDetectionAI.Infrastructure.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options) { }
        public DbSet<Scan> Scans => Set<Scan>();

        public DbSet<ThreatResult> ThreatResults => Set<ThreatResult>();

        public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
        public DbSet<ThreatKnowledge> ThreatKnowledgeBase => Set<ThreatKnowledge>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Scan>()
                .HasOne(x => x.ThreatResult)
                .WithOne(x => x.Scan)
                .HasForeignKey<ThreatResult>(x => x.ScanId);

            base.OnModelCreating(modelBuilder);
        }
    }
}
