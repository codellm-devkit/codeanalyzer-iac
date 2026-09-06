package reconcile

import (
	"context"
	"errors"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// transientDeadlock is the error Neo4j raises when two writers create the same
// constraint at once. Neo4j documents it as retryable, so the analyzer must not
// let it end a generation.
func transientDeadlock() error {
	return &neo4j.Neo4jError{Code: "Neo.TransientError.Transaction.DeadlockDetected", Msg: "ForsetiClient[transactionId=51]"}
}

// TestCreateConstraintsRetriesTransientError is the regression: one deadlock on
// the first attempt must be retried, not returned, and the constraint must
// exist once the retry lands.
func TestCreateConstraintsRetriesTransientError(t *testing.T) {
	session := &fakeSession{errs: []error{transientDeadlock()}}
	store := &BoltStore{driver: fakeDriver{session: session}}

	if err := store.createConstraints(context.Background(), []string{"CREATE CONSTRAINT c IF NOT EXISTS FOR (n:Artifact) REQUIRE n.id IS UNIQUE"}); err != nil {
		t.Fatalf("createConstraints after one transient deadlock: %v", err)
	}
	if got, want := len(session.created), 1; got != want {
		t.Fatalf("constraints created = %d, want %d", got, want)
	}
	if session.attempts != 2 {
		t.Fatalf("attempts = %d, want 2 (one failure, one retry)", session.attempts)
	}
	if session.autocommit != 0 {
		t.Fatalf("autocommit runs = %d, want 0: schema statements must go through a retrying managed transaction", session.autocommit)
	}
}

// TestCreateConstraintsFailsClosedOnNonRetryableError keeps the fail-closed
// guarantee: a real schema conflict still aborts the generation before any data
// is written, and is not retried.
func TestCreateConstraintsFailsClosedOnNonRetryableError(t *testing.T) {
	refusal := &neo4j.Neo4jError{Code: "Neo.ClientError.Schema.ConstraintCreationFailed", Msg: "duplicate ids"}
	session := &fakeSession{errs: []error{refusal}}
	store := &BoltStore{driver: fakeDriver{session: session}}

	err := store.createConstraints(context.Background(), []string{"CREATE CONSTRAINT c IF NOT EXISTS FOR (n:Artifact) REQUIRE n.id IS UNIQUE"})
	var reported *neo4j.Neo4jError
	if !errors.As(err, &reported) || reported.Code != refusal.Code {
		t.Fatalf("createConstraints error = %v, want the driver's %s unchanged", err, refusal.Code)
	}
	if session.attempts != 1 {
		t.Fatalf("attempts = %d, want 1: a non-retryable refusal must not be retried", session.attempts)
	}
	if len(session.created) != 0 {
		t.Fatalf("constraints created = %d, want 0", len(session.created))
	}
}

// TestCreateConstraintsStopsRetryingOnCancelledContext keeps a cancelled
// analysis from retrying a doomed statement forever.
func TestCreateConstraintsStopsRetryingOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &fakeSession{errs: []error{transientDeadlock(), transientDeadlock(), transientDeadlock()}, cancel: cancel}
	store := &BoltStore{driver: fakeDriver{session: session}}

	err := store.createConstraints(ctx, []string{"CREATE CONSTRAINT c IF NOT EXISTS FOR (n:Artifact) REQUIRE n.id IS UNIQUE"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("createConstraints error = %v, want context.Canceled", err)
	}
	if session.attempts != 1 {
		t.Fatalf("attempts = %d, want 1: cancellation must stop the retries", session.attempts)
	}
}

// fakeDriver hands createConstraints one scripted session instead of a live
// connection, so the retry behaviour can be exercised without a server.
type fakeDriver struct {
	neo4j.DriverWithContext
	session neo4j.SessionWithContext
}

func (d fakeDriver) NewSession(context.Context, neo4j.SessionConfig) neo4j.SessionWithContext {
	return d.session
}

// fakeSession scripts one error per attempt. ExecuteWrite stands in for the
// driver's managed transaction: it re-runs the unit of work while the error is
// retryable and the context is live, which is the behaviour the fix relies on.
// Run counts autocommit use, which is how the deadlock escaped in the first
// place.
type fakeSession struct {
	neo4j.SessionWithContext
	errs       []error
	attempts   int
	autocommit int
	created    []string
	cancel     context.CancelFunc
}

func (s *fakeSession) attempt(cypher string) error {
	var err error
	if s.attempts < len(s.errs) {
		err = s.errs[s.attempts]
	}
	s.attempts++
	if err == nil {
		s.created = append(s.created, cypher)
	}
	if s.cancel != nil {
		s.cancel()
	}
	return err
}

func (s *fakeSession) Run(_ context.Context, cypher string, _ map[string]any, _ ...func(*neo4j.TransactionConfig)) (neo4j.ResultWithContext, error) {
	s.autocommit++
	if err := s.attempt(cypher); err != nil {
		return nil, err
	}
	return fakeResult{}, nil
}

func (s *fakeSession) ExecuteWrite(ctx context.Context, work neo4j.ManagedTransactionWork, _ ...func(*neo4j.TransactionConfig)) (any, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value, err := work(fakeTransaction{session: s})
		if err == nil || !neo4j.IsRetryable(err) {
			return value, err
		}
	}
}

func (s *fakeSession) Close(context.Context) error { return nil }

type fakeTransaction struct {
	neo4j.ManagedTransaction
	session *fakeSession
}

func (t fakeTransaction) Run(_ context.Context, cypher string, _ map[string]any) (neo4j.ResultWithContext, error) {
	if err := t.session.attempt(cypher); err != nil {
		return nil, err
	}
	return fakeResult{}, nil
}

type fakeResult struct{ neo4j.ResultWithContext }

func (fakeResult) Consume(context.Context) (neo4j.ResultSummary, error) { return nil, nil }
