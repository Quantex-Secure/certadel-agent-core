using System;

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AcmeManager.Core.Storage.Migrations
{
    /// <inheritdoc />
    public partial class AddVerificationAndMaintenanceWindow : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "MaintenanceWindowJson",
                table: "Renewals",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "Verified",
                table: "Certificates",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "VerifiedAt",
                table: "Certificates",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MaintenanceWindowJson",
                table: "Renewals");

            migrationBuilder.DropColumn(
                name: "Verified",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "VerifiedAt",
                table: "Certificates");
        }
    }
}