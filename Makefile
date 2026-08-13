.PHONY: test demo fmt

test:
	go test ./...

demo:
	go run ./cmd/demo

fmt:
	gofmt -w cmd internal
