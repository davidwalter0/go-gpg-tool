bin/gpg-sign-tool: $(shell find src -type f -name "*.go")
	GOPATH=$(shell pwd ) \
	go build -tags netgo -ldflags '-w -s' \
		-o $@ -v src/gpg-sign-tool.go

clean:
	rm -v go-gpg-tool

.PHONY: clean
