# Suggested commands (developer quick reference)

# Verify Go toolchain

go version

# Manage modules

go mod tidy

# Build (library-level check)

go build ./...

# Run tests

go test ./... -v

# Static analysis and vet

go vet ./...

# Formatting

gofmt -w .
# (optional) if you use goimports or gofumpt:
# go install golang.org/x/tools/cmd/goimports@latest
# goimports -w .

# Lint (if you install golangci-lint or staticcheck)
# golangci-lint run
# staticcheck ./...

# To inspect dependencies

go list -m all

# Notes about running code that uses this repo
# - The Store uses Pebble and takes a filesystem path; provide a temp dir for tests or a configured path.
# - There are no binaries in this repo; to try integration, write a small `main` elsewhere that imports this package.

# Useful shell helpers (Linux / zsh)

# Run tests and stop on first failure

go test ./... -failfast

# Run tests for a single package

go test ./ -v

# Quick compile check
	go test ./... -run TestName -v  # target a single test
