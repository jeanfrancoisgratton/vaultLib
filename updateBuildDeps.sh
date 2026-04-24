#!/usr/bin/env bash
set -euo pipefail

go get -u github.com/hashicorp/vault/api
go mod tidy
