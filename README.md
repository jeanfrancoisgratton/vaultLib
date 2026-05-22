# VAULTLIB

---

<img src="./images/vaultLib.jpeg" alt="vault lib logo" height="400" /><br>

---

A lightweight HashiCorp Vault KV secret engine library for Go applications.

This library intentionally keeps a small API surface. It currently covers
read-only and read-write access to KV secrets. Vault administration is out of
scope.

## Install

```bash
go get github.com/jeanfrancoisgratton/vaultLib
```

## Configuration

The `Config` struct is shared across all subpackages. It is defined once in
`shared` and re-exported by each subpackage, so you only need to import the
subpackage you use.

```go
cfg := writer.Config{
    Address:   "https://vault.example.net:8200",
    Token:     "",           // empty: use VAULT_TOKEN, then ~/.vault-token
    MountPath: "containers", // KV mount name, not containers/data
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

---

## Reader subpackage

### Read a whole secret

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

### Read one field

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

### Optional fallback behavior

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

---

## Writer subpackage

The `writer` subpackage supports creating, modifying, and removing KV secrets.
It handles both KV v1 and KV v2 engines transparently: the correct API paths
are selected automatically by querying `sys/mounts` at client construction
time. If that query fails (e.g. due to policy restrictions), KV v2 is assumed.

```go
import "github.com/jeanfrancoisgratton/vaultLib/writer"
```

All methods have a `Context` variant (e.g. `WriteSecretContext`) for
propagating deadlines and cancellation. The non-context versions use
`context.Background()`.

### Required Vault policies

Write operations require broader permissions than reads. The minimum policy for
the examples in this section, using a KV v2 mount named `containers`:

```hcl
path "containers/data/*" {
  capabilities = ["create", "update"]
}

path "containers/metadata/*" {
  capabilities = ["read", "delete", "list"]
}

path "containers/delete/*" {
  capabilities = ["update"]
}

path "containers/destroy/*" {
  capabilities = ["update"]
}
```

For KV version detection, the token also needs:

```hcl
path "sys/mounts/containers" {
  capabilities = ["read"]
}
```

If this path is not accessible the library silently defaults to KV v2, so the
`sys/mounts` permission is optional.

### Write a full secret

Creates the secret if it does not exist; for KV v2 each call produces a new
version.

```go
cfg := writer.Config{
    Address:   "https://vault.example.net:8200",
    MountPath: "containers",
}

client, err := writer.NewClient(cfg)
if err != nil {
    log.Fatal(err)
}

result, err := client.WriteSecret("monitoring_apps", map[string]interface{}{
    "grafana_password": "s3cr3t",
    "alertmanager_url": "http://alertmanager:9093",
}, writer.WriteOptions{})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("wrote version %d\n", result.Version)
```

For KV v2 this writes to:

```text
containers/data/monitoring_apps
```

#### Check-And-Set (KV v2)

Pass `EnableCAS: true` to prevent overwriting a concurrently modified secret.
`CASVersion` must match the current version; set it to `0` to require that the
secret does not yet exist.

```go
result, err := client.WriteSecret("monitoring_apps", data, writer.WriteOptions{
    EnableCAS:  true,
    CASVersion: 3, // secret must currently be at version 3
})
```

### Write a single field

Adds or overwrites one field while preserving all other fields. If the secret
does not exist it is created with only the supplied field. For KV v2 this
produces a new version.

```go
result, err := client.WriteSecretField("monitoring_apps", "grafana_password", "newpassword")
if err != nil {
    log.Fatal(err)
}
```

This is a read-modify-write operation. See [Consistency note](#consistency-note)
below.

### Delete a single field

Removes one field from an existing secret. Returns an error if the secret or
the field does not exist. For KV v2 this produces a new version with the field
absent.

```go
result, err := client.DeleteSecretField("monitoring_apps", "alertmanager_url")
if err != nil {
    log.Fatal(err)
}
```

This is also a read-modify-write operation.

### Delete a whole secret

Permanently erases a secret and all its data.

For KV v2 this deletes the metadata path, which removes every version and the
path itself in a single irreversible operation. Use `DestroySecret` if you only
want to permanently remove a specific version while keeping the path.

```go
err := client.DeleteSecret("monitoring_apps")
if err != nil {
    log.Fatal(err)
}
```

### Destroy a specific version (KV v2)

Permanently destroys a single version. The secret path and any other versions
are left intact. `opts.Version` selects the version; `0` destroys the latest
version.

```go
// Destroy version 2 explicitly.
err := client.DestroySecret("monitoring_apps", writer.DestroyOptions{Version: 2})

// Destroy the latest version.
err = client.DestroySecret("monitoring_apps", writer.DestroyOptions{})
```

For KV v1, which has no versioning, `DestroySecret` behaves like `DeleteSecret`
and `opts.Version` is ignored.

This writes to:

```text
containers/destroy/monitoring_apps
```

### Update an existing field

Checks that the field already exists and returns an error if it does not. If
the field is present, writes a new version with the updated value while
preserving all other fields.

Use this when you want a strict update that must not create a new field
accidentally. Use `WriteSecretField` when an upsert (create-or-update) is
acceptable.

```go
result, err := client.UpdateSecretField("monitoring_apps", "grafana_password", "rotatedpassword")
if err != nil {
    // err is non-nil when the field does not exist, the secret does not
    // exist, or Vault returns an error.
    log.Fatal(err)
}
```

### Consistency note

`WriteSecretField`, `DeleteSecretField`, and `UpdateSecretField` are all
read-modify-write operations. A concurrent write between the read and the write
steps will silently win. If strict consistency is required, read the secret
yourself, check the version, and call `WriteSecret` with `EnableCAS` and the
version you read:

```go
secret, err := readerClient.ReadSecret("monitoring_apps", reader.ReadOptions{})
if err != nil {
    log.Fatal(err)
}

secret.Data["grafana_password"] = "rotatedpassword"

result, err := writerClient.WriteSecret("monitoring_apps", secret.Data, writer.WriteOptions{
    EnableCAS:  true,
    CASVersion: secret.Version,
})
```

### KV engine version

Call `KVVersion()` on a constructed client to inspect which engine version was
detected:

```go
client, _ := writer.NewClient(cfg)
fmt.Printf("KV engine version: %d\n", client.KVVersion())
```

### Error handling

All writer errors carry context about the operation that failed. Errors from a
sealed vault, network failures, and policy violations are reported distinctly:

| Condition                   | Error message contains                                     |
|-----------------------------|------------------------------------------------------------|
| Vault sealed or unreachable | `vault is sealed or unavailable` / `vault is sealed`       |
| Network failure             | `vault service unreachable`                                |
| Invalid token / policy      | `invalid Vault token or insufficient policy`               |
| CAS mismatch                | `check CAS version or KV engine configuration`             |
| Rate limit                  | `vault rate limit exceeded`                                |
| Secret / path not found     | `secret path does not exist or is unauthorized`            |
