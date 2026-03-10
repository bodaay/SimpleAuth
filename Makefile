APP        := simpleauth
VERSION    := $(shell cat VERSION 2>/dev/null | tr -d '[:space:]')
GIT_DIRTY  := $(shell git diff --quiet 2>/dev/null && echo "" || echo "-dirty")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS    := -s -w -X main.Version=$(VERSION)$(GIT_DIRTY) -X main.BuildTime=$(BUILD_TIME)

.PHONY: build run test clean release tag bump-patch bump-minor bump-major

## build: compile for the current platform
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o $(APP) .

## run: build and run locally
run: build
	./$(APP)

## test: run all tests
test:
	go test -count=1 ./...

## clean: remove build artifacts
clean:
	rm -rf $(APP) dist/

## release: cross-compile for all platforms (uses build.sh)
release:
	./build.sh

## tag: create a git tag for the current VERSION and push it
tag:
	@echo "Tagging v$(VERSION)"
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	git push origin "v$(VERSION)"

## bump-patch: 0.1.0 -> 0.1.1
bump-patch:
	@V=$(VERSION); \
	MAJOR=$$(echo $$V | cut -d. -f1); \
	MINOR=$$(echo $$V | cut -d. -f2); \
	PATCH=$$(echo $$V | cut -d. -f3); \
	NEW="$$MAJOR.$$MINOR.$$((PATCH + 1))"; \
	echo "$$NEW" > VERSION; \
	echo "Bumped: $$V -> $$NEW"

## bump-minor: 0.1.0 -> 0.2.0
bump-minor:
	@V=$(VERSION); \
	MAJOR=$$(echo $$V | cut -d. -f1); \
	MINOR=$$(echo $$V | cut -d. -f2); \
	NEW="$$MAJOR.$$((MINOR + 1)).0"; \
	echo "$$NEW" > VERSION; \
	echo "Bumped: $$V -> $$NEW"

## bump-major: 0.1.0 -> 1.0.0
bump-major:
	@V=$(VERSION); \
	MAJOR=$$(echo $$V | cut -d. -f1); \
	NEW="$$((MAJOR + 1)).0.0"; \
	echo "$$NEW" > VERSION; \
	echo "Bumped: $$V -> $$NEW"

## help: show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
