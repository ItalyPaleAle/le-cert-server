.PHONY: lint test test-race gen-config check-config-diff

lint:
	golangci-lint run -c .golangci.yaml

test:
	go test -tags unit ./...

test-race:
	CGO_ENABLED=1 go test -race -tags unit ./...

gen-config:
	go run ./tools/gen-config

# Ensure gen-config ran
check-config-diff: gen-config
	git diff --exit-code config.sample.yaml docs/Configuration.md
