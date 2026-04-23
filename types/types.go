// vclt
// Written by J.F. Gratton <jean-francois@famillegratton.net>
// Original timestamp: 2025/05/29 16:02
// Original filename: src/types/types.go

package types

var (
	VaultAuthToken     string
	VaultServerAddress string
	KVEngineMountPath  string
	KVSecretVersion    int
	KVSecretField      string
	Quiet              bool
	OutputFormat       string
	LogLevel           string
)

// Exit (error) codes

type ErrorInfoStruct struct {
	Int2StringCode string `json:"int2stringcode"`
	Msg            string `json:"msg"`
}

const (
	ErrVaultAuthTokenMissing = iota + 1
	ErrVaultServerAddressMissing
	ErrVaultInit
	ErrReadSecret
	ErrExtractData
	ErrFieldNotFound
	ErrInvalidPath
	ErrVaultUnavailable
	ErrVaultSealed
	ErrVaultInvalidAuth
)

// The map format is :
// Error code (int), Error name (string[0]), Error description (string[1])
var ErrorMessages = map[int]ErrorInfoStruct{
	ErrVaultAuthTokenMissing:     {"ERR_VAULTTOKENMISSING", "No Vault auth token provided"},
	ErrVaultServerAddressMissing: {"ERR_VAULTADDRESSMISSING", "No Vault server address provided"},
	ErrVaultInit:                 {"ERR_VAULTINIT", "Error initializing Vault client"},
	ErrReadSecret:                {"ERR_READSECRET", "Error reading secret from Vault"},
	ErrExtractData:               {"ERR_EXTRACTDATA", "Error extracting secret data"},
	ErrFieldNotFound:             {"ERR_FIELDNOTFOUND", "Requested field not found in secret"},
	ErrInvalidPath:               {"ERR_INVALIDSECRETPATH", "Secret path does not exist"},
	ErrVaultUnavailable:          {"ERR_VAULTUNAVAILABLE", "Vault server unavailable"},
	ErrVaultSealed:               {"ERR_VAULTSEALED", "Vault is sealed"},
	ErrVaultInvalidAuth:          {"ERR_VAULT_INVALIDAUTH", "Vault auth token is invalid"},
}
