.PHONY: test integration demo showcase fmt

test:
	go test ./...

integration:
	go test -tags=integration -count=1 ./internal/mcpproxy

demo:
	go run ./cmd/demo

showcase:
	go run ./cmd/showcase

fmt:
	gofmt -w cmd internal
