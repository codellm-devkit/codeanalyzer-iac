.PHONY: build sync-schema test race vet schema-check fuzz-smoke test-live test-live-head

# VERSION is the one version the binary reports: --version prints it and every
# analysis document is stamped with it. Override it for a release build.
VERSION ?= 0.1.0-dev

build:
	go build -ldflags "-X main.version=$(VERSION)" -o caniac ./cmd/codeanalyzer-iac

sync-schema:
	cp schema.json internal/contract/schema.json
	cp schema.neo4j.json internal/contract/schema.neo4j.json

test:
	go test ./...

race:
	go test -race ./...

# schema-check fails on any drift between the accepted contract files, the
# copies the binary embeds, and the catalog the emitter generates.
schema-check:
	cmp schema.json internal/contract/schema.json
	cmp schema.neo4j.json internal/contract/schema.neo4j.json
	go test ./internal/contract ./internal/emit/neo4j

# fuzz-smoke is the short, deterministic-duration lane CI runs. A longer
# campaign is `go test ./internal/dialects/helm -run '^$$' -fuzz <target>`.
fuzz-smoke:
	go test ./internal/dialects/helm -run '^$$' -fuzz FuzzHelmTemplateNeverPanics -fuzztime=10s
	go test ./internal/dialects/helm -run '^$$' -fuzz FuzzHelmValuesNeverPanics -fuzztime=10s
	go test ./internal/dialects/helm -run '^$$' -fuzz FuzzHelmChartNeverPanics -fuzztime=10s
	go test ./internal/dialects/helm -run '^$$' -fuzz FuzzHelmConfigNeverPanics -fuzztime=10s
	go test ./internal/dialects/helm -run '^$$' -fuzz FuzzHelmValuesSchemaNeverPanics -fuzztime=10s
	go test ./internal/dialects/helm -run '^$$' -fuzz FuzzRenderedDocumentsNeverPanic -fuzztime=10s

# The live acceptance gate needs a network, Helm 4.2.4 and a disposable Neo4j.
# It is build-tagged so `make test` stays offline. See README.md.
test-live:
	go test -tags=live ./tests/live -count=1

# The moving-head lane analyzes each repository's declared default branch. It
# reports the resolved commits and fails visibly on semantic drift; it never
# rewrites an expectation.
test-live-head:
	CANIAC_LIVE_REF_MODE=head go test -tags=live ./tests/live -count=1

vet:
	go vet ./...
	go vet -tags=live ./...
