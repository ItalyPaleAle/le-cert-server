.PHONY: lint test test-race gen-config check-config-diff gen-dns-providers check-dns-providers-diff

lint:
	golangci-lint run -c .golangci.yaml

test:
	go test -tags unit ./...

test-race:
	CGO_ENABLED=1 go test -race -tags unit ./...

gen-config:
	go tool gen-config

# Ensure gen-config ran
check-config-diff: gen-config
	git diff --exit-code config.sample.yaml config.md

gen-dns-providers:
	go tool gen-dns-providers

check-dns-providers-diff: gen-dns-providers
	git diff --exit-code pkg/config/provider_*.go pkg/config/dnsproviders_gen.go docs/content/dns-providers
