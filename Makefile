.PHONY: test integration demo fmt

test:
	go test ./...

integration:
	go test -tags=integration -count=1 ./internal/mcpproxy

demo:
	go run ./cmd/demo

fmt:
	gofmt -w cmd internal
