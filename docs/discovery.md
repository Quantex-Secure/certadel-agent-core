# Network discovery contract

Each acme-manager node makes itself discoverable so a central management console
can find, identify, and (eventually) manage it. Two complementary mechanisms:

## 1. mDNS / DNS-SD (local subnet, zero-config)

The node advertises a DNS-SD service via multicast DNS:

- **Service type:** `_acme-manager._tcp` (`.local` domain)
- **Instance name:** the node's friendly name (defaults to the machine name)
- **Port:** `9443`
- **TXT records:**
  | key | example | meaning |
  |---|---|---|
  | `product` | `acme-manager` | identifies the software |
  | `id` | `dd866b0f-…` | stable node id (GUID) |
  | `name` | `WEB01` | friendly name |
  | `fqdn` | `host.example.com` | reachable hostname for the API |
  | `version` | `0.1.0` | software version |

Browse with any DNS-SD client (`dns-sd -B _acme-manager._tcp`, `avahi-browse`,
`multicast-dns`, Makaretu, etc.). mDNS does **not** cross routers/subnets.

On by default; disable by setting `discovery.enabled` = `false` (takes effect on
restart).

## 2. HTTP identity endpoint (any subnet)

For routed networks, a console can scan an address range and probe:

```
GET https://<host>:9443/.well-known/acme-manager      (anonymous)
```

```json
{
  "product": "acme-manager",
  "nodeId": "3f2a9c4e-7b1d-4e8a-9c55-0d6e2f1a8b47",
  "name": "WEB01",
  "hostname": "WEB01",
  "fqdn": "host.example.com",
  "version": "0.1.0",
  "os": "Windows",
  "apiPort": 9443
}
```

Anonymous and **non-sensitive by design** — identity only, never certificates,
accounts, or secrets. The presence of this endpoint (and a `product` of
`acme-manager`) is how a console confirms a host is a node. The node serves a
self-signed cert until an ACME cert is issued for its own FQDN, so console probes
should not pin/verify the chain during discovery.

## Node identity

`nodeId` is generated once on first run and persisted in the settings table
(`node.id`). It is stable across restarts and upgrades and is the key a console
uses to track a node across hostname/IP changes.

## Console integration sketch

1. Discover nodes via mDNS on local segments **and** by probing
   `/.well-known/acme-manager` across known ranges; de-duplicate on `nodeId`.
2. Present the fleet (name, fqdn, version, last-seen).
3. Authenticate to each node for management actions (management APIs require auth;
   discovery does not). Cross-node auth / enrollment is a future addition.
