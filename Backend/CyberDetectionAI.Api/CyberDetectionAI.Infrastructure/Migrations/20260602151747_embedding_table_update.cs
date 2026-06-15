using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberDetectionAI.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class embedding_table_update : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "RiskScore",
                table: "ThreatKnowledgeBase",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "Status",
                table: "ThreatKnowledgeBase",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RiskScore",
                table: "ThreatKnowledgeBase");

            migrationBuilder.DropColumn(
                name: "Status",
                table: "ThreatKnowledgeBase");
        }
    }
}
