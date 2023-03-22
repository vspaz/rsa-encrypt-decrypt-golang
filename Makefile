BINARY_NAME=cryptonite

all: build
build:
	go build -ldflags="-s -w" -o $(BINARY_NAME) examples/main.go; upx $(BINARY_NAME)

.PHONY: test
test:
	go test -race -v ./...

.PHONY: clean
clean:
	rm -f $(BINARY_NAME)

.PHONY: style-fix
style-fix:
	gofmt -w .

.PHONY: lint
lint:
	golangci-lint run

.PHONY: upgrade
upgrade:
	go mod tidy
	go get -u all ./...