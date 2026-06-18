| Release | Date       | Comments                                                                                                                                   |
|---------|------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| 1.5.0   | 2026.06.18 | Added `SoftDeleteSecret` / `SoftDeleteSecretContext` + one-shot helper; `DeleteOptions.Versions` is now fully implemented                  |
| 1.4.3   | 2026.06.17 | If a secret version is set, `opts.FallbackToLatestAvailable` has to be set to false in `validateReadOptions()`                             |
| 1.4.2   | 2026.06.15 | Fixed number representation in version number                                                                                              |
| 1.4.1   | 2026.06.15 | Fixed error propagation in ListSecrets() that silently swallowed an error and returned secrets at v0                                       |
| 1.4.0   | 2026.06.15 | Added ListSecrets() to list all secrets in a KV engine, optionally returning the secret version number                                     |
| 1.3.0   | 2026.06.10 | Added a SealStatus() to get generic info on how the Vault was sealed<br>Used to find out how many key parts are needed to unseal the Vault | 
| 1.2.0   | 2026.06.03 | Refactored Read() and Write(), added an amdin subpackage, GO version upgrade -> 1.26.4                                                     |
| 1.1.0   | n/a        | Unreleased version                                                                                                                         |
| 1.0.2   | 2026.04.24 | Initial version                                                                                                                            |
