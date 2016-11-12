define tags
git tag $(git log --format=%h -n1)
endef
define date
date -u +%Y.%m.%d.%H.%M
endef
define commit
git log --format=%h -n1
endef

args:='-s -w -X main.Tag=$(shell $(tags)) -X main.Build=$(shell $(date)) -X main.Commit=$(shell $(commit))'

bin/gpg-sign-tool: $(shell find src -type f -name "*.go")
	GOPATH=$(shell pwd ) \
	go build -tags netgo \
		-ldflags $(args) \
		-o $@ -v src/gpg-sign-tool.go

clean:
	rm -f bin/gpg-sign-tool

.PHONY: clean
