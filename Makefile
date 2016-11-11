go-gpg-tool: $(shell find src -type f -name "*.go")
	GOPATH=$(shell pwd ) go build -v src/go-gpg-tool.go

clean:
	rm -v go-gpg-tool

.PHONY: clean
