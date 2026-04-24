# VAULTLIB

---

<img src="./images/vaultLib.jpeg" alt="vault lib logo" height="400" /><br>

---

A lightweight HashiCorp Vault KV v2 reader library for Go applications.

This library intentionally keeps a small API surface. It is currently focused on
read-only access to KV v2 secrets, not on administering Vault itself.

More capabilities (write secrets, Vault administration, etc) will be added later.
For now the read capabilities were the more pressing needs.

## Install

```bash
go get github.com/jeanfrancoisgratton/vaultLib
```

## Configuration

```go
cfg := reader.Config{
    Address:   "https://vault.example.net:8200",
    Token:     "",           // empty: use VAULT_TOKEN, then ~/.vault-token
    MountPath: "containers", // KV v2 mount name, not containers/data
}
```

Supported environment fallbacks:

| Config field     | Environment fallback                  |
|------------------|---------------------------------------|
| `Token`          | `VAULT_TOKEN`, then `~/.vault-token`  |
| `Address`        | `VAULT_ADDR`                          |
| `Namespace`      | `VAULT_NAMESPACE`                     |
| `CACertPath`     | `VAULT_CACERT`                        |
| `CAPath`         | `VAULT_CAPATH`                        |
| `ClientCertPath` | `VAULT_CLIENT_CERT`                   |
| `ClientKeyPath`  | `VAULT_CLIENT_KEY`                    |
| `TLSServerName`  | `VAULT_TLS_SERVER_NAME`               |
| `TLSSkipVerify`  | `VAULT_SKIP_VERIFY`                   |

## Read a whole secret

Given a KV v2 mount named `containers` and a secret named `monitoring_apps`:

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"

    "github.com/jeanfrancoisgratton/vaultLib/reader"
)

func main() {
    cfg := reader.Config{
        Address:   "https://vault.example.net:8200",
        Token:     "",
        MountPath: "containers",
    }

    client, err := reader.NewClient(cfg)
    if err != nil {
        log.Fatal(err)
    }

    secret, err := client.ReadSecret("monitoring_apps", reader.ReadOptions{})
    if err != nil {
        log.Fatal(err)
    }

    payload, err := json.MarshalIndent(secret.Data, "", "  ")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(string(payload))
}
```

This reads from:

```text
containers/data/monitoring_apps
```

## Read one field

```go
value, err := client.ReadSecretField("monitoring_apps", "grafana_password", 0)
if err != nil {
    log.Fatal(err)
}

password, ok := value.(string)
if !ok {
    log.Fatalf("grafana_password is not a string; got %T", value)
}
```

The version argument uses KV v2 semantics:

- `0`: latest version
- `>0`: explicit version

## Optional fallback behavior

By default, a read does **not** require access to the KV metadata endpoint.

If you explicitly want to recover from a deleted/unavailable latest version by
reading the newest available non-deleted version, enable fallback:

```go
secret, err := client.ReadSecret("monitoring_apps", reader.ReadOptions{
    FallbackToLatestAvailable: true,
})
```

This requires Vault policy access to both paths:

```hcl
path "containers/data/monitoring_apps" {
  capabilities = ["read"]
}

path "containers/metadata/monitoring_apps" {
  capabilities = ["read"]
}
```
