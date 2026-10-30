.PHONY: test
test:
	go tool ginkgo -v -r -cover -covermode=atomic

# golangci-lint, through `go tool` like the other tools: its default set
# (errcheck, govet, ineffassign, staticcheck, unused) and gofumpt, which is
# .golangci.yml; `make fmt` applies what the formatter would change.
.PHONY: fmt
fmt:
	go tool golangci-lint fmt

.PHONY: lint
lint:
	go tool golangci-lint run ./...

.PHONY: coverage
coverage:
	go tool ginkgo -r -coverprofile=coverage.out -covermode=atomic ./...
	go tool octocov ls-files
