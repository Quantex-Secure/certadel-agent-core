using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AcmeManager.Core.Storage.Migrations
{
    /// <inheritdoc />
    public partial class AddRenewalFailureTracking : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "ConsecutiveFailures",
                table: "Renewals",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "LastRunWarning",
                table: "Renewals",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ConsecutiveFailures",
                table: "Renewals");

            migrationBuilder.DropColumn(
                name: "LastRunWarning",
                table: "Renewals");
        }
    }
}