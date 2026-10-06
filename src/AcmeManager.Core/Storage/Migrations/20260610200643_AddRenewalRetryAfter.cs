using System;

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AcmeManager.Core.Storage.Migrations
{
    /// <inheritdoc />
    public partial class AddRenewalRetryAfter : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "RetryAfter",
                table: "Renewals",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RetryAfter",
                table: "Renewals");
        }
    }
}