.PHONY: sync-schema test test-live test-live-head vet

sync-schema:
	cp schema.json internal/contract/schema.json
	cp schema.neo4j.json internal/contract/schema.neo4j.json

test:
	go test ./...

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
