using System;

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AcmeManager.Core.Storage.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Accounts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    DirectoryUrl = table.Column<string>(type: "TEXT", nullable: false),
                    ContactEmail = table.Column<string>(type: "TEXT", nullable: false),
                    AccountKeyEncrypted = table.Column<byte[]>(type: "BLOB", nullable: false),
                    KeyId = table.Column<string>(type: "TEXT", nullable: true),
                    EabKeyIdEncrypted = table.Column<byte[]>(type: "BLOB", nullable: true),
                    EabHmacEncrypted = table.Column<byte[]>(type: "BLOB", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    RegisteredAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Accounts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Secrets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    EncryptedValue = table.Column<byte[]>(type: "BLOB", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    LastUsedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Secrets", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Settings",
                columns: table => new
                {
                    Key = table.Column<string>(type: "TEXT", nullable: false),
                    Value = table.Column<string>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Settings", x => x.Key);
                });

            migrationBuilder.CreateTable(
                name: "Renewals",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    AccountId = table.Column<Guid>(type: "TEXT", nullable: false),
                    SourceJson = table.Column<string>(type: "TEXT", nullable: false),
                    ValidationJson = table.Column<string>(type: "TEXT", nullable: false),
                    StoresJson = table.Column<string>(type: "TEXT", nullable: false),
                    InstallationsJson = table.Column<string>(type: "TEXT", nullable: false),
                    RenewalWindowDays = table.Column<int>(type: "INTEGER", nullable: false),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    LastAttemptAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    LastSuccessAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Renewals", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Renewals_Accounts_AccountId",
                        column: x => x.AccountId,
                        principalTable: "Accounts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "Certificates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    RenewalId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Thumbprint = table.Column<string>(type: "TEXT", nullable: false),
                    Subject = table.Column<string>(type: "TEXT", nullable: false),
                    SansJson = table.Column<string>(type: "TEXT", nullable: false),
                    NotBefore = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    NotAfter = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    IssuedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    StoreReferencesJson = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Certificates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Certificates_Renewals_RenewalId",
                        column: x => x.RenewalId,
                        principalTable: "Renewals",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "History",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    RenewalId = table.Column<Guid>(type: "TEXT", nullable: true),
                    At = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    Message = table.Column<string>(type: "TEXT", nullable: false),
                    DurationMs = table.Column<long>(type: "INTEGER", nullable: false),
                    ExceptionJson = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_History", x => x.Id);
                    table.ForeignKey(
                        name: "FK_History_Renewals_RenewalId",
                        column: x => x.RenewalId,
                        principalTable: "Renewals",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_Name",
                table: "Accounts",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_RenewalId",
                table: "Certificates",
                column: "RenewalId");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_Thumbprint",
                table: "Certificates",
                column: "Thumbprint");

            migrationBuilder.CreateIndex(
                name: "IX_History_At",
                table: "History",
                column: "At");

            migrationBuilder.CreateIndex(
                name: "IX_History_RenewalId",
                table: "History",
                column: "RenewalId");

            migrationBuilder.CreateIndex(
                name: "IX_Renewals_AccountId",
                table: "Renewals",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_Renewals_Name",
                table: "Renewals",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Secrets_Name",
                table: "Secrets",
                column: "Name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Certificates");

            migrationBuilder.DropTable(
                name: "History");

            migrationBuilder.DropTable(
                name: "Secrets");

            migrationBuilder.DropTable(
                name: "Settings");

            migrationBuilder.DropTable(
                name: "Renewals");

            migrationBuilder.DropTable(
                name: "Accounts");
        }
    }
}