GO          ?= go
BIN_DIR     ?= bin
RSP42       := $(BIN_DIR)/rsp42
CONFIG      ?= config/config.yaml
LDFLAGS     := -s -w

# Test-data sources (override SGP26_SRC with a local path to avoid downloading).
SGP26_SRC ?= https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2025/01/SGP.26_v3.0.2-2026_files_v2.zip
UPP_SRC   ?= https://github.com/osmocom/pysim/archive/refs/heads/master.tar.gz

.PHONY: all build test vet lint fmt tidy clean run-smdpp run-smds migrate testdata seed ci

all: build

build: ## build the rsp42 binary (provides both smdpp and smds roles)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(RSP42) ./cmd/rsp42

test: ## run all tests
	$(GO) test ./...

vet: ## run go vet
	$(GO) vet ./...

fmt: ## gofmt the tree
	gofmt -w cmd internal

tidy: ## tidy go.mod
	$(GO) mod tidy

lint: ## run golangci-lint (must be installed)
	golangci-lint run

clean: ## remove build output and local databases
	rm -rf $(BIN_DIR) db *.db *.db-wal *.db-shm audit.log

run-smdpp: build ## run the SM-DP+ role
	$(RSP42) smdpp --config $(CONFIG)

run-smds: build ## run the SM-DS role
	$(RSP42) smds --config $(CONFIG)

migrate: build ## apply database migrations (both roles; DB=dp|ds|all)
	$(RSP42) admin migrate --config $(CONFIG) --db $(or $(DB),all)

testdata: ## extract SGP.26 certificates and TS.48 UPP templates
	@test -n "$(UPP_SRC)" || { echo "error: set UPP_SRC=<TS.48 UPP tree, .zip or .tar.gz>"; exit 1; }
	./scripts/extract-testdata.sh --sgp26 "$(SGP26_SRC)" --upp "$(UPP_SRC)"

seed: build ## import UPP templates and personalization into the database
	$(RSP42) admin upp import --config $(CONFIG) --dir testdata/upp
	$(RSP42) admin personalization import --config $(CONFIG) --file testdata/personalization/profiles.csv

ci: build vet test ## what CI runs
