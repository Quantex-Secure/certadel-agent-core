<p align="center"><img src="branding/certadel-logo.svg" alt="Certadel" width="320"></p>

# Certadel Agent — core

Automated TLS certificate management for servers, from **any ACME certificate
authority** (Let's Encrypt, ZeroSSL, Google Trust Services, or your own internal ACME
CA). The agent runs as a background service on each server, issues and renews
certificates, installs them where they are actually served, **verifies the new
certificate is live**, and rolls back if it is not. A web console and a REST
management API are served on `https://<host>:9443`.

This repository holds the shared source — the engine, plugins, web console and
tests. Installers are built from the per-platform repositories, which include this
one as a git submodule:

| Platform | Repository | Package |
| --- | --- | --- |
| Windows Server (IIS) | [certadel-agent-windows](https://github.com/Quantex-Secure/certadel-agent-windows) | `.msi` → Windows Service |
| Linux (systemd) | [certadel-agent-linux](https://github.com/Quantex-Secure/certadel-agent-linux) | `.tar.gz` → systemd unit |
| Synology DSM 7.2+ | [certadel-agent-synology](https://github.com/Quantex-Secure/certadel-agent-synology) | `.spk` → Package Center |

Download installers from each platform repository's **Releases** page.

## What it does

- **Issue and renew** from any ACME v2 CA, with EAB support. Accounts, renewals and
  history live in a local SQLite database.
- **Validate** with HTTP-01 (filesystem or self-hosted listener) or DNS-01: Azure DNS,
  Cloudflare, AWS Route 53, Google Cloud DNS, Namecheap, a script, or manual.
- **Install** into IIS bindings (SNI-aware), the Windows certificate store, PEM/PFX
  files, HAProxy, Apache, Tomcat, Synology DSM (certificate + service bindings), or
  the agent's own `:9443` endpoint.
- **Verify** every renewal by connecting to each endpoint and comparing the served
  thumbprint; roll back all installers if any endpoint still serves the old
  certificate. A skipped check is recorded as *unverified*, never as success.
- **Schedule** with per-renewal maintenance windows, exponential back-off, and
  rate-limit protection.
- **Discover** what a host actually serves (IIS bindings, HAProxy `crt` sources)
  and reconcile it against what renews it; inventory an AD CS CA.
- **Import** existing renewals from win-acme and acme.sh, then hand off so the old
  tool stops renewing.
- **Alert** after repeated failures (log + webhook, Slack/Discord compatible).
- **Sign in** with the host's own accounts — Windows (`LogonUser`, domain accounts
  included), Linux PAM, or DSM — restricted to an administrators group by default.

## Build from source

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download) (pinned in
`global.json`). Everything here is plain `net10.0` and builds on Windows, Linux and
macOS.

```bash
dotnet build CertadelAgent.slnx -c Release
dotnet test  CertadelAgent.slnx -c Release
```

The end-to-end issuance tests run against [Pebble](https://github.com/letsencrypt/pebble)
when it is present (`pwsh scripts/download-pebble.ps1`) and skip otherwise.

Run the agent locally (the console comes up on `https://localhost:9443`):

```bash
dotnet run --project src/AcmeManager.Service
```

## Layout

| Path | Contents |
| --- | --- |
| `src/AcmeManager.Core` | ACME engine, scheduler, verification, storage, secrets |
| `src/AcmeManager.Service` | Host: Kestrel, auth, management API (`/api/v1`), importers, CLI verbs |
| `src/AcmeManager.Web` | Blazor web console |
| `src/AcmeManager.Plugins.*` | Sources, validators, stores and installers (IIS, Linux, Synology, DNS providers) |
| `src/AcmeManager.Plugins.Contracts` | Plugin API for third-party plugins |
| `src/AcmeManager.Api.Contracts` | Management API DTOs |
| `tests/AcmeManager.Tests` | Unit and integration tests |

Internal identifiers (assembly names, the `AcmeManager` service name, data paths)
predate the Certadel name and are kept so existing installs keep upgrading in place.

## Network use

The agent talks to the ACME CA and DNS provider APIs you configure. Optional features
add outbound traffic: LAN discovery announces the agent over mDNS (Settings →
Discovery, can be switched off), the Namecheap validator looks up the host's public IP
because Namecheap's API requires a whitelisted caller address, and failure alerts go
to the webhook URL you set. There is no telemetry.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0](LICENSE). Copyright © Quantex Secure.
