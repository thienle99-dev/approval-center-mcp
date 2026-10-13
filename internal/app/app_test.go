package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"log/slog"
)

func testService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	policy := filepath.Join(dir, "policies.yaml")
	if e := os.WriteFile(policy, []byte("version: test-1\npolicies:\n  - id: test\n    action_type: ssh.command\n    target: test\n    executor: ssh-commander\n    risk: high\n    minimum_approvers: 1\n    ttl_seconds: 120\n"), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("DB_PATH", filepath.Join(dir, "db.sqlite"))
	t.Setenv("AGENT_TOKEN", strings.Repeat("a", 48))
	t.Setenv("ADMIN_TOKEN", strings.Repeat("b", 48))
	t.Setenv("POLICY_FILE", policy)
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	s, e := New(context.Background(), slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestClaimIsSingleUseUnderConcurrency(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	execToken := strings.Repeat("c", 48)
	if _, e := s.db.Exec(`INSERT INTO executors(id,name,token_hash,created_at) VALUES(?,?,?,?)`, "ssh-commander", "SSH", tokenHash(execToken), now()); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(`INSERT INTO approval_requests(id,requester_id,executor_id,target_id,action_type,specification,digest,policy_version,risk,reason,status,minimum_approvers,allowed_approvers,created_at,expires_at,updated_at,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "R1", "agent", "ssh-commander", "test", "ssh.command", `{"parameters":{"command":"true"}}`, strings.Repeat("d", 64), "test-1", "HIGH", "test", "APPROVED", 1, "[]", now(), time.Now().Add(time.Minute).Format(time.RFC3339Nano), now(), "key"); e != nil {
		t.Fatal(e)
	}
	h := s.Handler()
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			body, _ := json.Marshal(ClaimInput{RequestID: "R1", ActionDigest: strings.Repeat("d", 64), AttemptID: string(rune('a' + n))})
			r := httptest.NewRequest(http.MethodPost, "/v1/executors/ssh-commander/claim", strings.NewReader(string(body)))
			r.Header.Set("Authorization", "Bearer "+execToken)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			codes <- w.Code
		}(n)
	}
	wg.Wait()
	close(codes)
	wins, denied := 0, 0
	for code := range codes {
		if code == 200 {
			wins++
		}
		if code == 409 || code == 403 {
			denied++
		}
	}
	if wins != 1 || denied != 1 {
		t.Fatalf("claim outcomes: success=%d denied=%d", wins, denied)
	}
	var state string
	if e := s.db.QueryRowContext(ctx, "SELECT status FROM approval_requests WHERE id='R1'").Scan(&state); e != nil || state != "CLAIMED" {
		t.Fatalf("state=%s err=%v", state, e)
	}
}

func TestClaimRejectsWrongDigestAndExecutor(t *testing.T) {
	s := testService(t)
	token := strings.Repeat("c", 48)
	_, _ = s.db.Exec(`INSERT INTO executors(id,name,token_hash,created_at) VALUES(?,?,?,?)`, "ssh-commander", "SSH", tokenHash(token), now())
	_, _ = s.db.Exec(`INSERT INTO approval_requests(id,requester_id,executor_id,target_id,action_type,specification,digest,policy_version,risk,reason,status,minimum_approvers,allowed_approvers,created_at,expires_at,updated_at,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "R2", "agent", "ssh-commander", "test", "ssh.command", `{}`, strings.Repeat("d", 64), "test-1", "HIGH", "test", "APPROVED", 1, "[]", now(), time.Now().Add(time.Minute).Format(time.RFC3339Nano), now(), "key")
	for _, tc := range []struct{ name, token, digest string }{{"digest", token, strings.Repeat("e", 64)}, {"executor", strings.Repeat("x", 48), strings.Repeat("d", 64)}} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(ClaimInput{RequestID: "R2", ActionDigest: tc.digest, AttemptID: tc.name})
			r := httptest.NewRequest(http.MethodPost, "/v1/executors/ssh-commander/claim", strings.NewReader(string(b)))
			r.Header.Set("Authorization", "Bearer "+tc.token)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code < 400 {
				t.Fatalf("expected denial, got %d", w.Code)
			}
		})
	}
}

func TestExecutorCanReportOnlyItsClaimedExecution(t *testing.T) {
	s := testService(t)
	token := strings.Repeat("c", 48)
	_, _ = s.db.Exec(`INSERT INTO executors(id,name,token_hash,created_at) VALUES(?,?,?,?)`, "ssh-commander", "SSH", tokenHash(token), now())
	_, e := s.db.Exec(`INSERT INTO approval_requests(id,requester_id,executor_id,target_id,action_type,specification,digest,policy_version,risk,reason,status,minimum_approvers,allowed_approvers,created_at,expires_at,updated_at,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "R3", "agent", "ssh-commander", "test", "ssh.command", `{}`, strings.Repeat("d", 64), "test-1", "HIGH", "test", "CLAIMED", 1, "[]", now(), time.Now().Add(time.Minute).Format(time.RFC3339Nano), now(), "key")
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.db.Exec(`INSERT INTO execution_claims(request_id,executor_id,attempt_id,claimed_at,status) VALUES(?,?,?,?,?)`, "R3", "ssh-commander", "attempt-3", now(), "CLAIMED")
	if e != nil {
		t.Fatal(e)
	}
	body := `{"request_id":"R3","execution_id":"exec-3","outcome":"SUCCEEDED","started_at":"2026-10-13T00:00:00Z","finished_at":"2026-10-13T00:00:01Z"}`
	r := httptest.NewRequest(http.MethodPost, "/v1/executors/ssh-commander/result", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("result report status %d: %s", w.Code, w.Body.String())
	}
	var state string
	if e = s.db.QueryRow("SELECT status FROM approval_requests WHERE id='R3'").Scan(&state); e != nil || state != "SUCCEEDED" {
		t.Fatalf("state=%s err=%v", state, e)
	}
}

func TestPolicyDenyAlwaysTakesPrecedence(t *testing.T) {
	s := testService(t)
	ctx := context.WithValue(context.Background(), requesterKey{}, "agent")
	_, _ = s.db.Exec(`INSERT INTO executors(id,name,token_hash,created_at) VALUES(?,?,?,?)`, "ssh-commander", "SSH", tokenHash(strings.Repeat("c", 48)), now())
	s.policies.Policies = []Policy{{ID: "allow-first", ActionType: "*", Target: "*", Executor: "*", Risk: "LOW", MinimumApprovers: 1, TTLSeconds: 120}, {ID: "deny-second", ActionType: "ssh.command", Target: "test", Executor: "ssh-commander", Risk: "CRITICAL", Deny: true}}
	_, e := s.create(ctx, RequestInput{ActionType: "ssh.command", TargetID: "test", ExecutorID: "ssh-commander", Action: map[string]any{"command": "true"}, Reason: "test", IdempotencyKey: "test"})
	if e == nil || !strings.Contains(e.Error(), "denied") {
		t.Fatalf("matching deny must override earlier allow, got %v", e)
	}
}

func TestMCPDiscoveryOnlyExposesNonApprovalTools(t *testing.T) {
	s := testService(t)
	httpServer := httptest.NewServer(s.Handler())
	defer httpServer.Close()
	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{token: strings.Repeat("a", 48)}}}
	session, e := mcp.NewClient(&mcp.Implementation{Name: "approval-test", Version: "1"}, nil).Connect(context.Background(), transport, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	tools, e := session.ListTools(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	got := map[string]bool{}
	for _, tool := range tools.Tools {
		got[tool.Name] = true
	}
	for _, name := range []string{"approval_request", "approval_get_status", "approval_list_requests", "approval_get_policy", "approval_get_audit"} {
		if !got[name] {
			t.Errorf("missing MCP tool %s", name)
		}
	}
	for name := range got {
		if strings.Contains(name, "approve") || strings.Contains(name, "grant") || strings.Contains(name, "override") {
			t.Errorf("prohibited approval authority tool exposed: %s", name)
		}
	}
}

func TestDatabaseFileIsPrivate(t *testing.T) {
	s := testService(t)
	info, e := os.Stat(s.cfg.DBPath)
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("database permissions = %o, want 600", info.Mode().Perm())
	}
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header = r.Header.Clone()
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}
