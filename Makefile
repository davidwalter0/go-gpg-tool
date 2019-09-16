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

.PHONY: get
get:
	GO111MODULE=on go get

bin/gpg-sign-tool: get $(shell find hostutils tools -type f -name "*.go")
	GO111MODULE=on \
	go build -tags netgo \
		-ldflags $(args) \
		-o $@ -v cmd/gpg-sign-tool/*.go
clean:
	rm -f bin/gpg-sign-tool

.PHONY: clean
