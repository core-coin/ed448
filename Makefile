PROFILING_FOLDER = profiling
GO_VERSION=$(shell go version | grep  -o 'go[[:digit:]]\.[[:digit:]]')

default: test lint

ci: deps-main lint test-main

internal: deps-internal lint test-internal

deps-main:
ifeq ($(GO_VERSION), go1.6)
	echo "$(GO_VERSION) is not a supported Go release. Skipping golint."
else ifeq ($(GO_VERSION), go1.7)
	echo "$(GO_VERSION) is not a supported Go release. Skipping golint."
else ifeq ($(GO_VERSION), go1.8)
	echo "$(GO_VERSION) is not a supported Go release. Skipping golint."
else
	go get -u golang.org/x/lint/golint
endif
	go get -t -v ./

deps-internal:
ifeq ($(GO_VERSION), go1.6)
	echo "$(GO_VERSION) is not a supported Go release. Skipping golint."
else ifeq ($(GO_VERSION), go1.7)
	echo "$(GO_VERSION) is not a supported Go release. Skipping golint."
else ifeq ($(GO_VERSION), go1.8)
	echo "$(GO_VERSION) is not a supported Go release. Skipping golint."
else
	go get -u golang.org/x/lint/golint
endif
	go get -t -v ./internal

lint:
ifeq ($(GO_VERSION), go1.6)
	echo "$(GO_VERSION) is not a supported Go release. Skipping golint."
else ifeq ($(GO_VERSION), go1.7)
	echo "$(GO_VERSION) is not a supported Go release. Skipping golint."
else ifeq ($(GO_VERSION), go1.8)
	echo "$(GO_VERSION) is not a supported Go release. Skipping golint."
else
	golint ./...
endif

vet:
	go vet ./...

test-all:
	go test -cover -v ./...

test-internal:
	go test -cover -v -run=^ ./internal

test-main:
	go test -cover -v -run=^ ./

test-v:
	go test -check.vv -cover ./...

bench:
	mkdir -p $(PROFILING_FOLDER)
	go test -check.vv -check.b -outputdir $(PROFILING_FOLDER) -cpuprofile cpu.pprof -memprofile memory.pprof $(RUN)
	mv ed448.test $(PROFILING_FOLDER)
	go tool pprof -top -output=$(PROFILING_FOLDER)/cpu-top.txt $(PROFILING_FOLDER)/ed448.test $(PROFILING_FOLDER)/cpu.pprof
	go tool pprof -top -output=$(PROFILING_FOLDER)/mem-top.txt $(PROFILING_FOLDER)/ed448.test $(PROFILING_FOLDER)/memory.pprof

clean:
	rm -rf $(PROFILING_FOLDER)

tidy:
	go mod tidy

ci-lint:
	golangci-lint run

race:
	go test -race -short $(go list ./... | grep -v /vendor/)

android:
	@go get -d golang.org/x/mobile/cmd/gomobile
	@gomobile init
	@gomobile bind -v -o ed448.aar -target=android ./mobile

ios:
	@go get -d golang.org/x/mobile/cmd/gomobile
	@gomobile init
	@gomobile bind -v -o ed448.xcframework -target=ios ./mobile
