.PHONY: sync-schema test vet

sync-schema:
	cp schema.json internal/contract/schema.json
	cp schema.neo4j.json internal/contract/schema.neo4j.json

test:
	go test ./...

vet:
	go vet ./...
