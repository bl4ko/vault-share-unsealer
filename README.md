# vault-share-unsealer

Unseal a HashiCorp Vault cluster that uses Shamir seals, without a cloud KMS and without a person.

Each host keeps one unseal key share in a systemd encrypted credential. The agent on each host watches every Vault pod. When a pod is initialized and sealed, the agent sends its share to `sys/unseal`. Vault unseals when enough hosts are up to reach the threshold. No single host holds enough material to unseal.

The agent connects to fixed IP addresses and verifies TLS against the Mozilla root store (`webpki-roots`) with the configured name as SNI and expected SAN. It does not need DNS, the Kubernetes API, or the host CA store.

## Usage

Download the static binary for your architecture from the [releases](https://github.com/bl4ko/vault-share-unsealer/releases) and check it:

```sh
sha256sum -c vault-share-unsealer-x86_64-unknown-linux-musl.sha256
install -m 0755 vault-share-unsealer-x86_64-unknown-linux-musl /usr/local/bin/vault-share-unsealer
```

`/etc/vault-share-unsealer/config.toml`:

```toml
interval_secs = 10

[[endpoint]]
name = "vault-0.example.com"
addr = "192.0.2.10:8200"

[[endpoint]]
name = "vault-1.example.com"
addr = "192.0.2.11:8200"
```

| Key | Default | Meaning |
| --- | --- | --- |
| `interval_secs` | `10` | Poll interval per endpoint (1 to 3600), with ±20 % jitter |
| `endpoint.name` | required | TLS server name (SNI and certificate SAN); a lowercase DNS name |
| `endpoint.addr` | required | `IP:port` to connect to |
| `extra_ca_file` | none | Extra PEM CA certificates, added to the WebPKI roots. For tests; leave unset in production |

Store the share as an encrypted credential. Read it from stdin so that it is not in the shell history or the process list:

```sh
systemd-creds encrypt --with-key=auto --name=vault-unseal-share - /etc/credstore.encrypted/vault-unseal-share
```

`/etc/systemd/system/vault-share-unsealer.service`:

```ini
[Unit]
Description=Vault Shamir share unsealer
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/vault-share-unsealer /etc/vault-share-unsealer/config.toml
LoadCredentialEncrypted=vault-unseal-share:/etc/credstore.encrypted/vault-unseal-share
DynamicUser=yes
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
PrivateUsers=yes
ProtectProc=invisible
ProcSubset=pid
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
LimitCORE=0
UMask=0077
MemoryMax=64M
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

The agent reads `$CREDENTIALS_DIRECTORY/vault-unseal-share`. It exits with status 1 if the credential is missing or empty, and with status 2 if the configuration is invalid.

## Behavior

- Each endpoint has its own loop: `GET /v1/sys/seal-status`, then `PUT /v1/sys/unseal` only if the pod is initialized and sealed.
- A network, TLS, or HTTP error, or a rejected share, starts exponential backoff for that endpoint only (interval × 2ⁿ, maximum 60 s). Other endpoints continue.
- If Vault rejects the combined key (for example, a stale part from an old share is in the unseal progress), Vault resets the progress. The agent logs `unseal rejected: invalid key` at warn level and sends its share again after backoff.
- Redirects and proxies are disabled.
- One log line per state change, for example `endpoint=vault-0.example.com sealed progress=1/3`. Under systemd, lines carry journald priorities.

## Threat model

Protects against:

- **Loss of one host.** A host stores one share. With threshold `t`, an attacker needs the decrypted credentials of `t` hosts: root on `t` hosts, or the host key (or TPM) and disk of `t` hosts.
- **Share theft at rest.** The share is encrypted with `systemd-creds` (TPM2 and host key when a TPM is present, host key otherwise). Only the service gets the plain text, through `LoadCredentialEncrypted=`, as a transient user (`DynamicUser=yes`).
- **Fake Vault endpoints.** The agent sends its share only after TLS verification against public roots for the configured name. A network attacker who redirects the IP address also needs a publicly trusted certificate for that name. That requires control of its DNS zone or of a CA.
- **Leaks through logs.** The agent never logs the share, request bodies, or `sys/unseal` response bodies. Unseal errors are mapped to fixed labels.

Does not protect against:

- Root on `t` share hosts at the same time.
- An attacker who can get a trusted certificate for an endpoint name (DNS zone or CA compromise) and can also route traffic to the endpoint address.
- An attacker with write access to the configuration (`extra_ca_file` or endpoint names). That attacker is root and can read the credential anyway.
- Denial of service. Keep enough manual shares offline to unseal Vault by hand.

## Development

```sh
cargo test
sh tests/gen-certs.sh /tmp/certs
VSU_BIN=target/release/vault-share-unsealer CERT_DIR=/tmp/certs sh tests/integration.sh
```

The integration test needs the `vault` binary. CI runs it in the `hashicorp/vault` image: it initializes Vault with 8 shares and threshold 3, seals it, and checks that:

- an agent with a wrong-SAN endpoint does not send its share;
- 3 agents unseal Vault within 30 s;
- the agents recover from a stale share in the unseal progress;
- no share appears in the logs;
- a missing or empty credential makes the agent exit non-zero.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
