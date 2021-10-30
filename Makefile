BINARY_NAME=cryptolib

all: build
build:
	go build -o $(BINARY_NAME) examples/main.go

.PHONY: test
test:
	go test -race ./pkg/ghttp -v

.PHONY: clean
clean:
	rm -f $(BINARY_NAME)

.PHONY: style-fix
style-fix:
	gofmt -w .

.PHONE: lint
lint:
	golangci-lint run