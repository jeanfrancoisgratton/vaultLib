# VAULTLIB

---

<img src="./images/vaultLib.jpeg" alt="vault lib logo" height="400" /><br>

---

A lightweight HashiCorp Vault library for Go applications, covering KV secret
engine reads and writes, ACL policy management, token lifecycle operations,
secrets engine mount management, and basic Vault administration
(seal/unseal).

## Table of Contents

- [Install](#install)
- [Package layout](#package-layout)
- [Configuration](#configuration)
  - [kv.Config](#kvconfig)
  - [Non-mount-scoped config: admin / policies / tokens / sys](#non-mount-scoped-config-admin--policies--tokens--sys)
- [kv subpackage](#kv-subpackage)
  - [Read a whole secret](#read-a-whole-secret)
  - [Read one field](#read-one-field)
  - [Optional fallback behavior](#optional-fallback-behavior)
  - [Write a full secret](#write-a-full-secret)
  - [Check-And-Set (KV v2)](#check-and-set-kv-v2)
  - [Write a single field](#write-a-single-field)
  - [Delete a single field](#delete-a-single-field)
  - [Delete a whole secret](#delete-a-whole-secret)
  - [Soft-delete specific versions (KV v2)](#soft-delete-specific-versions-kv-v2)
  - [Destroy a specific version (KV v2)](#destroy-a-specific-version-kv-v2)
  - [Update an existing field](#update-an-existing-field)
  - [KV engine version](#kv-engine-version)
  - [Consistency note](#consistency-note)
  - [Required Vault policies](#required-vault-policies)
  - [Error handling](#error-handling)
- [admin subpackage](#admin-subpackage)
  - [Unseal](#unseal)
  - [Seal](#seal)
  - [Seal status](#seal-status)
  - [Required Vault policies](#required-vault-policies-admin)
  - [Error handling](#error-handling-1)
- [policies subpackage](#policies-subpackage)
  - [List policies](#list-policies)
  - [Read a policy](#read-a-policy)
  - [Create a policy](#create-a-policy)
  - [Delete a policy](#delete-a-policy)
  - [Required Vault policies](#required-vault-policies-policies)
  - [Error handling](#error-handling-2)
- [tokens subpackage](#tokens-subpackage)
  - [Create a token](#create-a-token)
  - [Lookup a token](#lookup-a-token)
  - [Lookup self](#lookup-self)
  - [Renew a token](#renew-a-token)
  - [Revoke a token](#revoke-a-token)
  - [List accessors](#list-accessors)
  - [Required Vault policies](#required-vault-policies-tokens)
  - [Error handling](#error-handling-3)
- [sys subpackage](#sys-subpackage)
  - [List mounts](#list-mounts)
  - [Enable a KV engine](#enable-a-kv-engine)
  - [Edit a KV engine](#edit-a-kv-engine)
  - [Disable a KV engine](#disable-a-kv-engine)
  - [Required Vault policies](#required-vault-policies-sys)
  - [Error handling](#error-handling-4)

---

## Install

```bash
go get github.com/jeanfrancoisgratton/vaultLib
```

---

## Package layout

```
vaultLib/
├── shared/    — shared Config/SystemConfig types and environment resolution (internal use)
├── kv/        — KV secret engine: read, write, delete, destroy
├── admin/     — Vault administration: seal, unseal, seal status
├── policies/  — ACL policy management: list, read, create, delete
├── tokens/    — Token lifecycle: create, lookup, renew, revoke, list accessors
└── sys/       — Secrets engine mounts: list mounts, enable/edit/disable KV engines
```

`shared` is not meant to be imported directly. Every subpackage re-exports the
configuration type it needs as a type alias, so you only import the
subpackage you use. `admin.AdminConfig`, `policies.Config`, `tokens.Config`,
and `sys.Config` are all aliases for the same `shared.SystemConfig` type,
since none of those operations are scoped to a mount — see
[Non-mount-scoped config](#non-mount-scoped-config-admin--policies--tokens--sys).

---

## Configuration

### kv.Config

`kv.Config` is an alias for `shared.Config`. It holds the connection settings
and the KV mount path.

```go
cfg := kv.Config{
    Address:   "https://vault.example.net:8200",
    Token:     "",           // empty: resolved from VAULT_TOKEN, then ~/.vault-token
    MountPath: "containers", // KV mount name, not a full API path
}
```

`MountPath` must be the KV engine mount name only. If a secret lives at
`containers/data/monitoring_apps`, the mount path is `containers`.

Supported environment fallbacks:

| Config field     | Environment fallback                 |
|------------------|--------------------------------------|
| `Token`          | `VAULT_TOKEN`, then `~/.vault-token` |
| `Address`        | `VAULT_ADDR`                         |
| `Namespace`      | `VAULT_NAMESPACE`                    |
| `CACertPath`     | `VAULT_CACERT`                       |
| `CAPath`         | `VAULT_CAPATH`                       |
| `ClientCertPath` | `VAULT_CLIENT_CERT`                  |
| `ClientKeyPath`  | `VAULT_CLIENT_KEY`                   |
| `TLSServerName`  | `VAULT_TLS_SERVER_NAME`              |
| `TLSSkipVerify`  | `VAULT_SKIP_VERIFY`                  |

### Non-mount-scoped config: admin / policies / tokens / sys

`admin.AdminConfig`, `policies.Config`, `tokens.Config`, and `sys.Config` are
all type aliases for the same underlying `shared.SystemConfig` type. None of
them have a `MountPath` field, since policy, token, and mount-management
operations target Vault's system API rather than a specific KV engine.

A token is optional for `admin.Unseal` and `admin.SealStatus` (the vault
accepts those calls before authentication), but every policies, tokens, and
sys operation — and `admin.Seal` — does require one.

```go
cfg := admin.AdminConfig{ // identical shape to policies.Config / tokens.Config / sys.Config
    Address: "https://vault.example.net:8200",
    Token:   "", // resolved from VAULT_TOKEN, then ~/.vault-token when empty
}
```

> **Why one shared type instead of four?** `AdminConfig` was the first
> non-mount-scoped config type in this library. Rather than copying its
> environment-resolution logic (token, address, namespace, TLS settings) into
> `policies`, `tokens`, and `sys` a third and fourth time, that logic was
> promoted to `shared.SystemConfig` in v1.6.0, and `AdminConfig` became an
> alias for it. This is purely an internal change — `AdminConfig`'s fields,
> JSON tags, and resolution behavior are unchanged, so existing callers are
> unaffected.

The same TLS fields and environment fallbacks available on `kv.Config` are
supported:

| Config field     | Environment fallback                 |
|------------------|--------------------------------------|
| `Token`          | `VAULT_TOKEN`, then `~/.vault-token` |
| `Address`        | `VAULT_ADDR`                         |
| `Namespace`      | `VAULT_NAMESPACE`                    |
| `CACertPath`     | `VAULT_CACERT`                       |
| `CAPath`         | `VAULT_CAPATH`                       |
| `ClientCertPath` | `VAULT_CLIENT_CERT`                  |
| `ClientKeyPath`  | `VAULT_CLIENT_KEY`                   |
| `TLSServerName`  | `VAULT_TLS_SERVER_NAME`              |
| `TLSSkipVerify`  | `VAULT_SKIP_VERIFY`                  |

---

## kv subpackage

```go
import "github.com/jeanfrancoisgratton/vaultLib/kv"
```

The `kv` subpackage handles both KV v1 and KV v2 secret engines. The correct
API paths are selected automatically by querying `sys/mounts` at client
construction time. If that query fails (e.g. due to policy restrictions), KV
v2 is assumed.

All methods have a `Context` variant (e.g. `ReadSecretContext`,
`WriteSecretContext`) for propagating deadlines and cancellation. The
non-context versions use `context.Background()`.

### Read a whole secret

Given a KV v2 mount named `containers` and a secret path `monitoring_apps`:

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"

    "github.com/jeanfrancoisgratton/vaultLib/kv"
)

func main() {
    cfg := kv.Config{
        Address:   "https://vault.example.net:8200",
        MountPath: "containers",
    }

    client, err := kv.NewClient(cfg)
    if err != nil {
        log.Fatal(err)
    }

    secret, err := client.ReadSecret("monitoring_apps", kv.ReadOptions{})
    if err != nil {
        log.Fatal(err)
    }

    payload, _ := json.MarshalIndent(secret.Data, "", "  ")
    fmt.Println(string(payload))
}
```

This reads from `containers/data/monitoring_apps`.

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

The version argument uses KV v2 semantics: `0` means latest, any positive
integer selects that explicit version. Version is ignored for KV v1.

### Optional fallback behavior

By default, a read does not require access to the KV metadata endpoint.

If you want to recover from a deleted or unavailable latest version by reading
the newest non-deleted version instead, enable fallback:

```go
secret, err := client.ReadSecret("monitoring_apps", kv.ReadOptions{
    FallbackToLatestAvailable: true,
})
```

This requires policy access to both the data and metadata paths. See
[Required Vault policies](#required-vault-policies).

### Write a full secret

Creates the secret if it does not exist. For KV v2 each call produces a new
version; for KV v1 the secret is overwritten in place.

```go
result, err := client.WriteSecret("monitoring_apps", map[string]interface{}{
    "grafana_password": "s3cr3t",
    "alertmanager_url": "http://alertmanager:9093",
}, kv.WriteOptions{})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("wrote version %d\n", result.Version)
```

For KV v2 this writes to `containers/data/monitoring_apps`.

### Check-And-Set (KV v2)

Pass `EnableCAS: true` to prevent overwriting a concurrently modified secret.
`CASVersion` must match the current version number. Set it to `0` to require
that the secret does not yet exist.

```go
result, err := client.WriteSecret("monitoring_apps", data, kv.WriteOptions{
    EnableCAS:  true,
    CASVersion: 3, // secret must currently be at version 3
})
```

### Write a single field

Adds or overwrites one field while preserving all others. If the secret does
not exist it is created with only the supplied field. For KV v2 this produces a
new version.

```go
result, err := client.WriteSecretField("monitoring_apps", "grafana_password", "newpassword")
if err != nil {
    log.Fatal(err)
}
```

This is a read-modify-write operation. See [Consistency note](#consistency-note).

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

For KV v2 this deletes the metadata path, removing every version and the path
itself in a single irreversible operation. Use `DestroySecret` if you only want
to permanently remove a specific version while keeping the path and remaining
versions intact.

```go
err := client.DeleteSecret("monitoring_apps")
if err != nil {
    log.Fatal(err)
}
```

### Soft-delete specific versions (KV v2)

Marks one or more versions as deleted without removing the secret path or any
other versions. Soft-deleted versions can be recovered with an undelete
operation (not yet in this library, but available via the Vault API directly).
`opts.Versions` lists the versions to soft-delete; an empty or nil slice
soft-deletes the latest version.

```go
// Soft-delete version 3 only.
err := client.SoftDeleteSecret("monitoring_apps", kv.DeleteOptions{Versions: []int{3}})

// Soft-delete the latest version.
err = client.SoftDeleteSecret("monitoring_apps", kv.DeleteOptions{})
```

For KV v1, which has no versioning, `SoftDeleteSecret` behaves identically to
`DeleteSecret` and `opts.Versions` is ignored.

This calls `DELETE <mount>/delete/<path>` with `{"versions": [...]}`, which is
distinct from the metadata-delete that `DeleteSecret` issues. The path and
remaining versions stay intact.

### Destroy a specific version (KV v2)

Permanently destroys a single version. The secret path and any other versions
are left intact. `opts.Version` selects the version; `0` destroys the latest.

```go
// Destroy version 2 explicitly.
err := client.DestroySecret("monitoring_apps", kv.DestroyOptions{Version: 2})

// Destroy the latest version.
err = client.DestroySecret("monitoring_apps", kv.DestroyOptions{})
```

For KV v1, which has no versioning, `DestroySecret` behaves identically to
`DeleteSecret` and `opts.Version` is ignored.

### Update an existing field

Checks that the field already exists before writing. Returns an error if the
field is absent, leaving the secret unchanged. If the field is present it
writes a new version with the updated value while preserving all other fields.

Use this when you want a strict update that must not create a new field
accidentally. Use `WriteSecretField` when an upsert (create-or-update) is
acceptable.

```go
result, err := client.UpdateSecretField("monitoring_apps", "grafana_password", "rotatedpassword")
if err != nil {
    log.Fatal(err)
}
```

### KV engine version

Call `KVVersion()` on a constructed client to inspect which engine version was
detected:

```go
client, _ := kv.NewClient(cfg)
fmt.Printf("KV engine version: %d\n", client.KVVersion())
```

### Consistency note

`WriteSecretField`, `DeleteSecretField`, and `UpdateSecretField` are all
read-modify-write operations. A concurrent write between the internal read and
write steps will silently win. If strict consistency is required, read the
secret yourself, check the version, and call `WriteSecret` with `EnableCAS`:

```go
secret, err := client.ReadSecret("monitoring_apps", kv.ReadOptions{})
if err != nil {
    log.Fatal(err)
}

secret.Data["grafana_password"] = "rotatedpassword"

result, err := client.WriteSecret("monitoring_apps", secret.Data, kv.WriteOptions{
    EnableCAS:  true,
    CASVersion: secret.Version,
})
```

### Required Vault policies

Minimum policy for a KV v2 mount named `containers`:

```hcl
# Read operations
path "containers/data/monitoring_apps" {
  capabilities = ["read"]
}

# Required only when FallbackToLatestAvailable is enabled
path "containers/metadata/monitoring_apps" {
  capabilities = ["read"]
}

# Write operations
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

# Optional: KV engine version detection at client construction
path "sys/mounts/containers" {
  capabilities = ["read"]
}
```

If the `sys/mounts` path is not accessible the library silently defaults to
KV v2, so that permission is optional.

### Error handling

All errors carry context about the operation that failed:

| Condition                   | Error message contains                                  |
|-----------------------------|---------------------------------------------------------|
| Vault sealed or unreachable | `vault is sealed or unavailable` / `vault is sealed`    |
| Network failure             | `vault service unreachable`                             |
| Invalid token / policy      | `invalid Vault token or insufficient policy`            |
| CAS mismatch                | `check CAS version or KV engine configuration`          |
| Rate limit                  | `vault rate limit exceeded`                             |
| Secret / path not found     | `secret path does not exist or is unauthorized`         |

---

## admin subpackage

```go
import "github.com/jeanfrancoisgratton/vaultLib/admin"
```

The `admin` subpackage targets the Vault system API. It currently provides
`Unseal` and `Seal`. Both methods have a `Context` variant for deadline and
cancellation propagation.

### Unseal

Submits each key to the unseal endpoint in order, stopping as soon as the
vault reports it is open. Each submission produces one `UnsealResult` entry
so the caller can observe progress toward the threshold.

If the vault is already unsealed when `Unseal` is called, a single result with
`Sealed: false` is returned immediately without submitting any keys.

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeanfrancoisgratton/vaultLib/admin"
)

func main() {
    cfg := admin.AdminConfig{
        Address: "https://vault.example.net:8200",
    }

    keys := []string{
        "key-share-1",
        "key-share-2",
        "key-share-3",
    }

    results, err := admin.Unseal(cfg, keys)
    if err != nil {
        log.Fatal(err)
    }

    for _, r := range results {
        fmt.Printf("key %d applied — progress: %d/%d sealed: %v\n",
            r.KeyIndex, r.Progress, r.Threshold, r.Sealed)
    }
}
```

`UnsealResult` fields:

| Field       | Description                                                                    |
|-------------|--------------------------------------------------------------------------------|
| `KeyIndex`  | Zero-based index of the key in the input slice. `-1` means no key was needed.  |
| `Sealed`    | Whether the vault is still sealed after this key was applied.                  |
| `Progress`  | Number of key shares accepted so far toward the threshold.                     |
| `Threshold` | Total number of key shares required to unseal.                                 |

### Seal

Activates the Vault seal via `sys/seal`. The vault immediately stops serving
secret requests once sealed. Calling `Seal` on an already-sealed vault returns
nil.

`Seal` requires a token with `sudo` capability on `sys/seal`.

```go
cfg := admin.AdminConfig{
    Address: "https://vault.example.net:8200",
    Token:   "your-root-or-admin-token",
}

client, err := admin.NewClient(cfg)
if err != nil {
    log.Fatal(err)
}

if err := client.Seal(); err != nil {
    log.Fatal(err)
}

fmt.Println("vault is sealed")
```

### Seal status

Queries the Vault seal-status endpoint (`GET /v1/sys/seal-status`). **No
token is required** — this is one of the few unauthenticated Vault endpoints.
It is useful to discover the unseal threshold (`Threshold`) and total key
shares (`TotalShares`) before attempting to unseal, or simply to monitor seal
state.

```go
cfg := admin.AdminConfig{
    Address: "https://vault.example.net:8200",
    // Token is not required for this call.
}

status, err := admin.GetSealStatus(cfg)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("sealed: %v — need %d of %d key shares (progress: %d)\n",
    status.Sealed, status.Threshold, status.TotalShares, status.Progress)
```

Or with a reusable client:

```go
client, err := admin.NewClient(cfg)
if err != nil {
    log.Fatal(err)
}

status, err := client.SealStatus()
if err != nil {
    log.Fatal(err)
}
```

`SealStatusResult` fields:

| Field                | Description                                                                      |
|----------------------|----------------------------------------------------------------------------------|
| `Sealed`             | Whether the vault is currently sealed.                                           |
| `TotalShares`        | Total number of Shamir key shares (`n`) that exist.                              |
| `Threshold`          | Minimum shares required to unseal (`t`). This is the answer to "how many keys?" |
| `Progress`           | Key shares applied so far in an in-progress unseal attempt.                      |
| `Initialized`        | Whether the vault has been initialized.                                          |
| `ClusterName`        | Human-readable cluster name, if set.                                             |
| `ClusterID`          | Unique cluster identifier.                                                       |
| `RecoverySeal`       | Whether recovery seals (e.g. cloud KMS auto-unseal) are enabled.                |
| `StorageType`        | Storage backend in use (e.g. `raft`, `consul`).                                  |
| `HCPLinkStatus`      | HCP Link integration status, if configured.                                      |
| `HCPLinkResourceID`  | HCP resource ID associated with the cluster.                                     |

### Required Vault policies (admin)

```hcl
# Unseal and SealStatus — no token required; Vault accepts these before
# authentication. No policy entry needed.

# Seal
path "sys/seal" {
  capabilities = ["update", "sudo"]
}
```

### Error handling

| Condition              | Error message contains                          |
|------------------------|-------------------------------------------------|
| Network failure        | `vault service unreachable`                     |
| Invalid token / policy | `unauthorized — check token and namespace`      |
| Invalid key format     | `invalid unseal key format`                     |
| Rate limit              | `vault rate limit exceeded`                     |
| Vault unavailable      | `vault is unavailable`                          |
| Vault sealed (non-HTTP)| `vault is sealed`                               |

---

## policies subpackage

```go
import "github.com/jeanfrancoisgratton/vaultLib/policies"
```

The `policies` subpackage manages Vault ACL policies via `sys/policies/acl`.
All methods have a `Context` variant for deadline and cancellation
propagation.

### List policies

Returns every policy name, including the built-in `default` and `root`
policies.

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeanfrancoisgratton/vaultLib/policies"
)

func main() {
    cfg := policies.Config{
        Address: "https://vault.example.net:8200",
        Token:   "your-token",
    }

    names, err := policies.ListPolicies(cfg)
    if err != nil {
        log.Fatal(err)
    }

    for _, name := range names {
        fmt.Println(name)
    }
}
```

### Read a policy

```go
client, err := policies.NewClient(cfg)
if err != nil {
    log.Fatal(err)
}

policy, err := client.ReadPolicy("monitoring-readonly")
if err != nil {
    log.Fatal(err)
}

fmt.Println(policy.Rules)
```

Vault's underlying `GetPolicy` call returns an empty string with a `nil`
error when a policy doesn't exist, rather than a 404 — this is the same kind
of non-obvious behavior already handled specially for KV `LIST` calls.
`ReadPolicy` turns that empty result into an explicit
`policy "..." does not exist` error so callers don't have to special-case it.

`Policy.Rules` is the raw policy document exactly as Vault stores it (HCL or
JSON), in a single string — that's a faithful mirror of what the Vault API
returns, not a library limitation. Printing a multi-line `Rules` value
directly (as above) renders fine, but it can look garbled inside a table
cell, a log line, or an escaped JSON dump. For those cases, use
`RuleLines()` to get the document as `[]string`, one entry per line:

```go
for _, line := range policy.RuleLines() {
    fmt.Println(line)
}
```

`RuleLines()` is a display convenience only — a newline split, nothing
more. It does not parse HCL/JSON and has no notion of path blocks or
capabilities, so it can't tell you what a policy grants; `Rules` remains
the canonical representation (and the one `CreatePolicy` expects back
unchanged).

### Create a policy

```go
rules := `
path "containers/data/monitoring_apps" {
  capabilities = ["read"]
}
`

if err := client.CreatePolicy("monitoring-readonly", rules); err != nil {
    log.Fatal(err)
}
```

Vault's policy write endpoint has no separate create-vs-update verb: this is
an upsert, exactly like the underlying API. Callers that need strict
create-only semantics should call `ReadPolicy` first and check for a
not-found error.

### Delete a policy

```go
if err := client.DeletePolicy("monitoring-readonly"); err != nil {
    log.Fatal(err)
}
```

Vault itself refuses to delete the built-in `default` and `root` policies;
`DeletePolicy` does not duplicate that guard client-side and simply surfaces
Vault's rejection.

### Required Vault policies (policies)

```hcl
path "sys/policies/acl" {
  capabilities = ["list"]
}

path "sys/policies/acl/*" {
  capabilities = ["read", "create", "update", "delete"]
}
```

### Error handling

| Condition              | Error message contains                                       |
|-------------------------|---------------------------------------------------------------|
| Vault sealed or unreachable | `vault is sealed or unavailable` / `vault service unreachable` |
| Invalid token / policy  | `invalid Vault token or insufficient policy`                  |
| Policy not found        | `policy does not exist`                                       |
| Rate limit              | `vault rate limit exceeded`                                   |

---

## tokens subpackage

```go
import "github.com/jeanfrancoisgratton/vaultLib/tokens"
```

The `tokens` subpackage manages Vault tokens via `auth/token`. All methods
have a `Context` variant for deadline and cancellation propagation.

### Create a token

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeanfrancoisgratton/vaultLib/tokens"
)

func main() {
    cfg := tokens.Config{
        Address: "https://vault.example.net:8200",
        Token:   "your-token",
    }

    client, err := tokens.NewClient(cfg)
    if err != nil {
        log.Fatal(err)
    }

    renewable := true
    auth, err := client.CreateToken(tokens.CreateOptions{
        Policies:    []string{"monitoring-readonly"},
        TTL:         "1h",
        DisplayName: "monitoring-agent",
        Renewable:   &renewable,
        Orphan:      true,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(auth.ClientToken)
}
```

If `CreateOptions.RoleName` is set, the token is created against
`auth/token/create/<role>` instead, which takes precedence over `Orphan`
since a role's own constraints govern the result. Otherwise `Orphan` selects
between `auth/token/create-orphan` and `auth/token/create`.

`CreateOptions.Renewable` is a `*bool` rather than a plain `bool`, so a token
can be created without forcing a renewable value either way and instead
deferring to Vault's own default — the same `nil`-means-unset preference used
by `kv.WriteOptions.EnableCAS` for `CASVersion`.

### Lookup a token

```go
info, err := client.LookupToken(someTokenValue)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("policies: %v, ttl: %ds\n", info.Policies, info.TTL)
```

### Lookup self

Looks up the token currently configured on the client (`Config.Token`).

```go
self, err := client.LookupSelf()
if err != nil {
    log.Fatal(err)
}

fmt.Println(self.DisplayName)
```

### Renew a token

`increment` is the requested TTL increment in seconds; Vault treats it as
advisory and may return a shorter lease than requested. `0` lets Vault pick
its own increment.

```go
auth, err := client.RenewToken(someTokenValue, 3600)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("lease_duration: %ds\n", auth.LeaseDuration)
```

### Revoke a token

```go
if err := client.RevokeToken(someTokenValue); err != nil {
    log.Fatal(err)
}
```

This revokes the full lease/child-token tree under the token (Vault's
`RevokeTree`), not just the token itself — revoking a token near the root of
a tree is therefore broader than revoking that one token alone.

### List accessors

```go
accessors, err := client.ListAccessors()
if err != nil {
    log.Fatal(err)
}

for _, accessor := range accessors {
    fmt.Println(accessor)
}
```

There is no dedicated SDK helper for this on Vault's `TokenAuth` type, so
`ListAccessors` calls `LIST auth/token/accessors` directly via `Logical()` —
the same approach `kv.ListSecrets` uses for KV listings. As with KV listings,
a 404 from Vault (meaning "no accessors yet") is treated as zero accessors,
not an error.

### Required Vault policies (tokens)

```hcl
path "auth/token/create" {
  capabilities = ["create", "update"]
}

path "auth/token/create-orphan" {
  capabilities = ["create", "update"]
}

path "auth/token/create/*" {
  capabilities = ["create", "update"]
}

path "auth/token/lookup" {
  capabilities = ["create", "update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew" {
  capabilities = ["create", "update"]
}

path "auth/token/revoke" {
  capabilities = ["create", "update"]
}

path "auth/token/accessors" {
  capabilities = ["list"]
}
```

### Error handling

| Condition                    | Error message contains                                       |
|-------------------------------|---------------------------------------------------------------|
| Vault sealed or unreachable   | `vault is sealed or unavailable` / `vault service unreachable` |
| Invalid token / policy        | `invalid Vault token or insufficient policy`                  |
| Token / accessor not found    | `token or accessor does not exist`                             |
| Rate limit                    | `vault rate limit exceeded`                                   |

---

## sys subpackage

```go
import "github.com/jeanfrancoisgratton/vaultLib/sys"
```

The `sys` subpackage manages secrets engine mounts via `sys/mounts`. All
methods have a `Context` variant for deadline and cancellation propagation.

### List mounts

Returns every secret engine mount in Vault, not only KV engines.

```go
package main

import (
    "fmt"
    "log"

    "github.com/jeanfrancoisgratton/vaultLib/sys"
)

func main() {
    cfg := sys.Config{
        Address: "https://vault.example.net:8200",
        Token:   "your-token",
    }

    mounts, err := sys.ListMounts(cfg)
    if err != nil {
        log.Fatal(err)
    }

    for _, m := range mounts {
        if m.Type == "kv" {
            fmt.Printf("%s (kv v%s)\n", m.Path, m.KVVersion)
            continue
        }
        fmt.Printf("%s (%s)\n", m.Path, m.Type)
    }
}
```

`MountInfo.KVVersion` is populated only for `kv`-type mounts, parsed from
`Options["version"]`; it is empty for every other engine type.

### Enable a KV engine

```go
client, err := sys.NewClient(cfg)
if err != nil {
    log.Fatal(err)
}

err = client.EnableKVEngine("monitoring", sys.EnableKVOptions{
    Version:     2,
    Description: "monitoring stack secrets",
})
if err != nil {
    log.Fatal(err)
}
```

`Version` defaults to `2` when left at `0`, matching `vault secrets enable
kv`'s own default.

### Edit a KV engine

Tunes lease TTLs, listing visibility, and similar mount-level settings.
Fields left `nil` in `EditKVOptions` are left unchanged on the mount — the
same `nil`-means-unset preference used by `kv.WriteOptions.EnableCAS`.

```go
description := "monitoring stack secrets (rotated quarterly)"
ttl := "720h"

err = client.EditKVEngine("monitoring", sys.EditKVOptions{
    Description:     &description,
    DefaultLeaseTTL: &ttl,
})
if err != nil {
    log.Fatal(err)
}
```

### Disable a KV engine

```go
if err := client.DisableKVEngine("monitoring"); err != nil {
    log.Fatal(err)
}
```

This is irreversible: every secret stored under the mount, across all
versions, is destroyed along with it.

`EditKVEngine` and `DisableKVEngine` both confirm the target mount is
actually a `kv`-type engine before acting on it. Vault's underlying tune and
unmount calls are generic to any mount type, so without this pre-flight
check a typo'd or misremembered path could silently tune or unmount an
unrelated engine (e.g. database, pki) that happens to share the same generic
endpoint with KV.

### Required Vault policies (sys)

```hcl
path "sys/mounts" {
  capabilities = ["read"]
}

path "sys/mounts/*" {
  capabilities = ["read", "create", "update", "delete"]
}
```

### Error handling

| Condition                  | Error message contains                                       |
|------------------------------|---------------------------------------------------------------|
| Vault sealed or unreachable  | `vault is sealed or unavailable` / `vault service unreachable` |
| Invalid token / policy       | `invalid Vault token or insufficient policy`                  |
| Mount not found              | `mount does not exist`                                        |
| Mount type mismatch          | `not a kv engine`                                              |
| Rate limit                   | `vault rate limit exceeded`                                   |
