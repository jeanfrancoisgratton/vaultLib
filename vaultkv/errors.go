package vaultkv

import "fmt"

type ErrorInfo struct {
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

var ErrorMessages = map[int]ErrorInfo{
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

type Error struct {
	Title   string
	Message string
	Code    int
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Title == "" && e.Message == "" && e.Err != nil {
		return e.Err.Error()
	}
	if e.Title == "" {
		return e.Message
	}
	if e.Message == "" {
		return e.Title
	}
	return fmt.Sprintf("%s: %s", e.Title, e.Message)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func newError(code int, title, message string, err error) *Error {
	return &Error{Title: title, Message: message, Code: code, Err: err}
}
