# vaultLib → vaultlib v2.0.0 Migration Summary

## What Changed

Your `vaultLib` package has been renamed to `vaultlib` (lowercase) and versioned as **v2.0.0** to follow Go naming conventions.

### Key Updates

| Aspect | Old (v1.x) | New (v2.0+) |
|--------|-----------|------------|
| **Module name** | `github.com/jeanfrancoisgratton/vaultLib` | `github.com/jeanfrancoisgratton/vaultlib/v2` |
| **Import paths** | `github.com/jeanfrancoisgratton/vaultLib/admin` | `github.com/jeanfrancoisgratton/vaultlib/v2/admin` |
| **Functionality** | All features preserved | ✅ No changes |
| **API** | All function signatures | ✅ No changes |
| **Package structure** | admin, kv, policies, shared, sys, tokens | ✅ Same |

## What Was Updated in the Tarball

### 1. **go.mod**
```
- module github.com/jeanfrancoisgratton/vaultLib
+ module github.com/jeanfrancoisgratton/vaultlib/v2
```

### 2. **Files Updated**
- ✅ `README.md` — Install section and all code examples updated
- ✅ `CHANGELOG.md` — Added v2.0.0 entry with migration notes
- ✅ `current_pkg_version.md` — Updated to v2.0.0
- ✅ `vaultLib/doc.go` — New deprecation notice file for documentation
- ✅ All Go file headers (comments) — Changed "vaultLib" → "vaultlib"

### 3. **Subpackages** (unchanged code, same functionality)
- `admin/` — Seal, unseal, seal status
- `kv/` — KV secrets (read, write, backup, restore)
- `policies/` — ACL policy management
- `shared/` — Internal configuration types
- `sys/` — Secrets engine mounts
- `tokens/` — Token lifecycle management

## How to Migrate Your Tools

### Step 1: Update go.mod dependency
```bash
go get github.com/jeanfrancoisgratton/vaultlib/v2@v2.0.0
```

### Step 2: Update import statements
Replace all occurrences:

```go
// OLD
import "github.com/jeanfrancoisgratton/vaultLib/admin"
import "github.com/jeanfrancoisgratton/vaultLib/kv"
import "github.com/jeanfrancoisgratton/vaultLib/policies"
import "github.com/jeanfrancoisgratton/vaultLib/tokens"
import "github.com/jeanfrancoisgratton/vaultLib/sys"

// NEW
import "github.com/jeanfrancoisgratton/vaultlib/v2/admin"
import "github.com/jeanfrancoisgratton/vaultlib/v2/kv"
import "github.com/jeanfrancoisgratton/vaultlib/v2/policies"
import "github.com/jeanfrancoisgratton/vaultlib/v2/tokens"
import "github.com/jeanfrancoisgratton/vaultlib/v2/sys"
```

### Step 3: No code logic changes needed
All function signatures, types, and behavior remain identical. Just update the import paths and you're done.

## Publishing to pkg.go.dev

### Option A: Simple Tag & Push
```bash
git tag -a v2.0.0 -m 'Rename to lowercase: vaultlib'
git push origin v2.0.0
```

pkg.go.dev indexes automatically (~10 minutes).

### Option B: With GitHub Release (Recommended)
1. Push the tag as above
2. Create a GitHub Release from the tag with release notes
3. Both v1.x and v2.0.0 will be indexed separately on pkg.go.dev

## What About vclt and customHelpers?

If `vaultlib` is a dependency in `vclt` or `customHelpers`:

**In customHelpers/v6 (or wherever vaultLib is imported):**
```go
// Update go.mod
require github.com/jeanfrancoisgratton/vaultlib/v2 v2.0.0

// Update imports in code
import "github.com/jeanfrancoisgratton/vaultlib/v2/admin"
```

Then update customHelpers/v6 accordingly.

## Backward Compatibility Note

⚠️ **Important**: Old code importing from `github.com/jeanfrancoisgratton/vaultLib` will NOT work with v2.0.0 because the module name itself changed. This is intentional—Go modules require you to be explicit about major version changes.

This is a **semver-compliant breaking change** (major version bump), even though the actual functionality doesn't break. The change is purely about naming hygiene.

Since you control all consumers (vclt, customHelpers, etc.), migrating them together is straightforward.

## Verification

After deploying, verify on pkg.go.dev:
- Old version: `github.com/jeanfrancoisgratton/vaultLib` (v1.x) — still available
- New version: `github.com/jeanfrancoisgratton/vaultlib` (v2.0.0+) — latest, with new package name

Both can coexist on pkg.go.dev for reference by users.

## Questions?

Refer to the updated README.md in this tarball for complete documentation.
