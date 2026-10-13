package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

type Config struct {
	DBPath, AgentToken, AdminToken, PolicyPath, TelegramToken string
	TelegramUsers, TelegramChats                              map[int64]bool
}
type PolicyFile struct {
	Version  string   `yaml:"version"`
	Policies []Policy `yaml:"policies"`
}
type Policy struct {
	ID               string  `yaml:"id"`
	ActionType       string  `yaml:"action_type"`
	Target           string  `yaml:"target"`
	Requester        string  `yaml:"requester"`
	Executor         string  `yaml:"executor"`
	Risk             string  `yaml:"risk"`
	Deny             bool    `yaml:"deny"`
	MinimumApprovers int     `yaml:"minimum_approvers"`
	RequiredRole     string  `yaml:"required_execution_role"`
	TTLSeconds       int     `yaml:"ttl_seconds"`
	AllowedApprovers []int64 `yaml:"allowed_approver_ids"`
}
type Service struct {
	db            *sql.DB
	cfg           Config
	policies      PolicyFile
	logger        *slog.Logger
	mux           *http.ServeMux
	notifications chan notification
}
type notification struct {
	id         string
	input      RequestInput
	spec, risk string
	expiry     time.Time
}
type requesterKey struct{}
type RequestInput struct {
	ActionType     string         `json:"action_type"`
	TargetID       string         `json:"target_id"`
	ExecutorID     string         `json:"executor_id"`
	Action         map[string]any `json:"action_specification"`
	Reason         string         `json:"reason"`
	Timeout        int            `json:"requested_timeout"`
	IdempotencyKey string         `json:"idempotency_key"`
}
type ClaimInput struct {
	RequestID    string `json:"request_id"`
	ActionDigest string `json:"expected_action_digest"`
	AttemptID    string `json:"claim_attempt_id"`
}

func New(ctx context.Context, logger *slog.Logger) (*Service, error) {
	cfg := Config{DBPath: env("DB_PATH", "/data/approval.db"), AgentToken: secretEnv("AGENT_TOKEN"), AdminToken: secretEnv("ADMIN_TOKEN"), PolicyPath: env("POLICY_FILE", "/etc/approval-center/policies.yaml"), TelegramToken: secretEnv("TELEGRAM_BOT_TOKEN"), TelegramUsers: ids(os.Getenv("TELEGRAM_ALLOWED_USER_IDS")), TelegramChats: ids(os.Getenv("TELEGRAM_ALLOWED_CHAT_IDS"))}
	if cfg.AgentToken == "" || cfg.AdminToken == "" {
		return nil, errors.New("AGENT_TOKEN and ADMIN_TOKEN must be configured")
	}
	if e := os.MkdirAll(filepath.Dir(cfg.DBPath), 0700); e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", cfg.DBPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Service{db: db, cfg: cfg, logger: logger, mux: http.NewServeMux(), notifications: make(chan notification, 64)}
	if e = s.migrate(ctx); e != nil {
		db.Close()
		return nil, e
	}
	if e = os.Chmod(cfg.DBPath, 0600); e != nil {
		db.Close()
		return nil, fmt.Errorf("secure database file: %w", e)
	}
	s.policies, e = loadPolicies(cfg.PolicyPath)
	if e != nil {
		db.Close()
		return nil, e
	}
	if _, e = db.ExecContext(ctx, `INSERT OR IGNORE INTO requesters(id,identity,token_hash,created_at) VALUES('agent','agent',?,?)`, tokenHash(cfg.AgentToken), now()); e != nil {
		db.Close()
		return nil, e
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "approval-center", Version: "0.1.0"}, nil)
	s.registerTools(server)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	s.mux.Handle("/mcp", s.requesterAuth(mcpHandler))
	s.routes()
	if cfg.TelegramToken != "" {
		go s.telegramLoop(ctx)
		for i := 0; i < 2; i++ {
			go s.notificationWorker(ctx)
		}
	}
	go s.expirer(ctx)
	return s, nil
}
func (s *Service) Close() error          { return s.db.Close() }
func (s *Service) Handler() http.Handler { return s.mux }
func (s *Service) migrate(ctx context.Context) error {
	_, e := s.db.ExecContext(ctx, `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS requesters(id TEXT PRIMARY KEY, identity TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS executors(id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approvers(id INTEGER PRIMARY KEY, telegram_user_id INTEGER NOT NULL UNIQUE, display_name TEXT NOT NULL, role TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approval_requests(id TEXT PRIMARY KEY, requester_id TEXT NOT NULL, executor_id TEXT NOT NULL, target_id TEXT NOT NULL, action_type TEXT NOT NULL, specification TEXT NOT NULL, digest TEXT NOT NULL, policy_version TEXT NOT NULL, risk TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL, minimum_approvers INTEGER NOT NULL, allowed_approvers TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, updated_at TEXT NOT NULL, idempotency_key TEXT NOT NULL, FOREIGN KEY(requester_id) REFERENCES requesters(id), UNIQUE(requester_id,idempotency_key));
CREATE INDEX IF NOT EXISTS request_status_expiry ON approval_requests(status,expires_at);
CREATE TABLE IF NOT EXISTS approval_decisions(id INTEGER PRIMARY KEY, request_id TEXT NOT NULL REFERENCES approval_requests(id), approver_id INTEGER NOT NULL REFERENCES approvers(id), decision TEXT NOT NULL, decided_at TEXT NOT NULL, UNIQUE(request_id,approver_id));
CREATE TABLE IF NOT EXISTS telegram_callbacks(token TEXT PRIMARY KEY, request_id TEXT NOT NULL REFERENCES approval_requests(id), decision TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT);
CREATE TABLE IF NOT EXISTS execution_claims(id INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE REFERENCES approval_requests(id), executor_id TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE, claimed_at TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS execution_results(id INTEGER PRIMARY KEY, request_id TEXT NOT NULL REFERENCES approval_requests(id), execution_id TEXT NOT NULL UNIQUE, started_at TEXT, finished_at TEXT, outcome TEXT NOT NULL, result_reference TEXT, error_summary TEXT);
CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY, request_id TEXT, actor_id TEXT NOT NULL, actor_type TEXT NOT NULL, event_type TEXT NOT NULL, event_json TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_request ON audit_events(request_id,id);
INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,CURRENT_TIMESTAMP);`)
	return e
}
func (s *Service) routes() {
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	s.mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if e := s.db.PingContext(r.Context()); e != nil {
			http.Error(w, "not ready", 503)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ready\n"))
	})
	s.mux.Handle("/v1/executors/", s.executorAuth(http.HandlerFunc(s.executorAPI)))
	s.mux.Handle("/v1/requests", s.requesterAuth(http.HandlerFunc(s.requesterAPI)))
	s.mux.Handle("/v1/requests/", s.requesterAuth(http.HandlerFunc(s.requesterAPI)))
	s.mux.Handle("/admin/", s.auth(s.cfg.AdminToken, http.HandlerFunc(s.adminAPI)))
}
func (s *Service) requesterAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/v1/requests" {
		var in RequestInput
		if !decode(w, r, &in) {
			return
		}
		out, e := s.create(r.Context(), in)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		writeJSON(w, out)
		return
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/requests/") {
		id := strings.TrimPrefix(r.URL.Path, "/v1/requests/")
		result := s.status(r.Context(), principal(r.Context()), id)
		if _, missing := result["error"]; missing {
			http.Error(w, "request not found", 404)
			return
		}
		writeJSON(w, result)
		return
	}
	http.NotFound(w, r)
}
func (s *Service) auth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == r.Header.Get("Authorization") || !secureEqual(got, token) {
			http.Error(w, "unauthorized", 401)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Service) requesterAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == r.Header.Get("Authorization") || got == "" {
			http.Error(w, "unauthorized", 401)
			return
		}
		var id string
		if s.db.QueryRowContext(r.Context(), "SELECT id FROM requesters WHERE token_hash=? AND enabled=1", tokenHash(got)).Scan(&id) != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requesterKey{}, id)))
	})
}
func (s *Service) executorAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		var id string
		if got == "" || s.db.QueryRowContext(r.Context(), "SELECT id FROM executors WHERE enabled=1 AND token_hash=?", tokenHash(got)).Scan(&id) != nil || pathExecutor(r.URL.Path) != id {
			http.Error(w, "unauthorized", 401)
			return
		}
		r.Header.Set("X-Executor-ID", id)
		next.ServeHTTP(w, r)
	})
}
func (s *Service) executorAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "not found", 404)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/result") {
		s.reportResult(w, r)
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/claim") {
		http.Error(w, "not found", 404)
		return
	}
	var in ClaimInput
	if !decode(w, r, &in) {
		return
	}
	execID := r.Header.Get("X-Executor-ID")
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	defer tx.Rollback()
	var state, storedExec, digest, expires, spec string
	e = tx.QueryRowContext(r.Context(), `SELECT status,executor_id,digest,expires_at,specification FROM approval_requests WHERE id=?`, in.RequestID).Scan(&state, &storedExec, &digest, &expires, &spec)
	if e != nil {
		http.Error(w, "request unavailable", 404)
		return
	}
	if state != "APPROVED" || storedExec != execID || digest != in.ActionDigest || in.AttemptID == "" {
		http.Error(w, "claim denied", 403)
		return
	}
	expiry, _ := time.Parse(time.RFC3339Nano, expires)
	if time.Now().After(expiry) {
		http.Error(w, "request expired", 403)
		return
	}
	res, e := tx.ExecContext(r.Context(), `INSERT INTO execution_claims(request_id,executor_id,attempt_id,claimed_at,status) VALUES(?,?,?,?,?)`, in.RequestID, execID, in.AttemptID, now(), "CLAIMED")
	if e != nil {
		http.Error(w, "already claimed", 409)
		return
	}
	_, _ = res.LastInsertId()
	_, e = tx.ExecContext(r.Context(), `UPDATE approval_requests SET status='CLAIMED',updated_at=? WHERE id=? AND status='APPROVED'`, now(), in.RequestID)
	if e != nil {
		http.Error(w, "claim failed", 409)
		return
	}
	s.auditTx(r.Context(), tx, in.RequestID, execID, "executor", "authorization_claimed", map[string]any{"attempt_id": in.AttemptID})
	if e = tx.Commit(); e != nil {
		http.Error(w, "claim failed", 409)
		return
	}
	writeJSON(w, map[string]any{"request_id": in.RequestID, "executor_id": execID, "action_digest": digest, "action_specification": json.RawMessage(spec), "status": "CLAIMED"})
}
func (s *Service) reportResult(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RequestID       string `json:"request_id"`
		ExecutionID     string `json:"execution_id"`
		Outcome         string `json:"outcome"`
		StartedAt       string `json:"started_at"`
		FinishedAt      string `json:"finished_at"`
		ResultReference string `json:"result_reference"`
		ErrorSummary    string `json:"error_summary"`
	}
	if !decode(w, r, &in) {
		return
	}
	switch in.Outcome {
	case "EXECUTING", "SUCCEEDED", "FAILED", "CANCELLED", "INDETERMINATE":
	default:
		http.Error(w, "invalid outcome", 400)
		return
	}
	if in.RequestID == "" || in.ExecutionID == "" || len(in.ResultReference) > 2048 || len(in.ErrorSummary) > 1024 {
		http.Error(w, "invalid result", 400)
		return
	}
	execID := r.Header.Get("X-Executor-ID")
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	defer tx.Rollback()
	var state, claimed string
	if tx.QueryRowContext(r.Context(), `SELECT q.status,c.executor_id FROM approval_requests q JOIN execution_claims c ON c.request_id=q.id WHERE q.id=?`, in.RequestID).Scan(&state, &claimed) != nil || claimed != execID {
		http.Error(w, "claim not found", 404)
		return
	}
	if state != "CLAIMED" && state != "EXECUTING" {
		http.Error(w, "request is terminal", 409)
		return
	}
	if in.Outcome == "EXECUTING" {
		_, e = tx.ExecContext(r.Context(), `UPDATE approval_requests SET status='EXECUTING',updated_at=? WHERE id=? AND status='CLAIMED'`, now(), in.RequestID)
	} else {
		_, e = tx.ExecContext(r.Context(), `UPDATE approval_requests SET status=?,updated_at=? WHERE id=? AND status IN ('CLAIMED','EXECUTING')`, in.Outcome, now(), in.RequestID)
	}
	if e != nil {
		http.Error(w, "state update failed", 409)
		return
	}
	_, e = tx.ExecContext(r.Context(), `INSERT INTO execution_results(request_id,execution_id,started_at,finished_at,outcome,result_reference,error_summary) VALUES(?,?,?,?,?,?,?) ON CONFLICT(execution_id) DO UPDATE SET outcome=excluded.outcome,finished_at=excluded.finished_at,result_reference=excluded.result_reference,error_summary=excluded.error_summary`, in.RequestID, in.ExecutionID, in.StartedAt, in.FinishedAt, in.Outcome, in.ResultReference, in.ErrorSummary)
	if e != nil {
		http.Error(w, "result persistence failed", 409)
		return
	}
	_, _ = tx.ExecContext(r.Context(), `UPDATE execution_claims SET status=? WHERE request_id=?`, in.Outcome, in.RequestID)
	s.auditTx(r.Context(), tx, in.RequestID, execID, "executor", "execution_"+strings.ToLower(in.Outcome), map[string]any{"execution_id": in.ExecutionID, "outcome": in.Outcome})
	if tx.Commit() != nil {
		http.Error(w, "result persistence failed", 409)
		return
	}
	writeJSON(w, map[string]any{"request_id": in.RequestID, "status": in.Outcome})
}
func (s *Service) adminAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" && r.URL.Path == "/admin/executors" {
		var in struct{ ID, Name, Token string }
		if !decode(w, r, &in) {
			return
		}
		if in.ID == "" || in.Name == "" || len(in.Token) < 32 {
			http.Error(w, "id, name and >=32 character token required", 400)
			return
		}
		h := sha256.Sum256([]byte(in.Token))
		_, e := s.db.ExecContext(r.Context(), `INSERT INTO executors(id,name,token_hash,created_at) VALUES(?,?,?,?)`, in.ID, in.Name, hex.EncodeToString(h[:]), now())
		if e != nil {
			http.Error(w, "executor registration failed", 409)
			return
		}
		s.audit(r.Context(), "", "admin", "admin", "executor_registered", map[string]any{"executor_id": in.ID})
		writeJSON(w, map[string]any{"registered": in.ID})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/admin/approvers" {
		var in struct {
			UserID      int64  `json:"telegram_user_id"`
			DisplayName string `json:"display_name"`
			Role        string `json:"role"`
		}
		if !decode(w, r, &in) {
			return
		}
		if in.UserID <= 0 || in.DisplayName == "" || in.Role == "" {
			http.Error(w, "invalid approver", 400)
			return
		}
		_, e := s.db.ExecContext(r.Context(), `INSERT INTO approvers(telegram_user_id,display_name,role,created_at) VALUES(?,?,?,?)`, in.UserID, in.DisplayName, in.Role, now())
		if e != nil {
			http.Error(w, "approver registration failed", 409)
			return
		}
		writeJSON(w, map[string]any{"registered": in.UserID})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/admin/requesters" {
		var in struct {
			ID       string `json:"id"`
			Identity string `json:"identity"`
			Token    string `json:"token"`
		}
		if !decode(w, r, &in) {
			return
		}
		if in.ID == "" || in.Identity == "" || len(in.Token) < 32 {
			http.Error(w, "id, identity and >=32 character token required", 400)
			return
		}
		_, e := s.db.ExecContext(r.Context(), `INSERT INTO requesters(id,identity,token_hash,created_at) VALUES(?,?,?,?)`, in.ID, in.Identity, tokenHash(in.Token), now())
		if e != nil {
			http.Error(w, "requester registration failed", 409)
			return
		}
		s.audit(r.Context(), "", "admin", "admin", "requester_registered", map[string]any{"requester_id": in.ID})
		writeJSON(w, map[string]any{"registered": in.ID})
		return
	}
	http.NotFound(w, r)
}

func (s *Service) registerTools(server *mcp.Server) {
	mcp.AddTool[RequestInput, map[string]any](server, &mcp.Tool{Name: "approval_request", Description: "Create an immutable proposal for an action. This never executes it.", InputSchema: objectSchema([]string{"action_type", "target_id", "executor_id", "action_specification", "reason", "idempotency_key"})}, func(ctx context.Context, _ *mcp.CallToolRequest, in RequestInput) (*mcp.CallToolResult, map[string]any, error) {
		out, e := s.create(ctx, in)
		return nil, out, e
	})
	type ID struct {
		RequestID string `json:"request_id"`
	}
	mcp.AddTool[ID, map[string]any](server, &mcp.Tool{Name: "approval_get_status", Description: "Get status of an approval request owned by the caller.", InputSchema: objectSchema([]string{"request_id"})}, func(ctx context.Context, _ *mcp.CallToolRequest, in ID) (*mcp.CallToolResult, map[string]any, error) {
		return nil, s.status(ctx, principal(ctx), in.RequestID), nil
	})
	type Empty struct{}
	mcp.AddTool[Empty, map[string]any](server, &mcp.Tool{Name: "approval_get_policy", Description: "Show non-sensitive configured policy summaries.", InputSchema: objectSchema(nil)}, func(context.Context, *mcp.CallToolRequest, Empty) (*mcp.CallToolResult, map[string]any, error) {
		return nil, map[string]any{"policy_version": s.policies.Version, "policies": s.policies.Policies}, nil
	})
	mcp.AddTool[Empty, map[string]any](server, &mcp.Tool{Name: "approval_list_requests", Description: "List recent approval requests.", InputSchema: objectSchema(nil)}, func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, map[string]any, error) {
		rows, e := s.db.QueryContext(ctx, "SELECT id,action_type,target_id,status,created_at,expires_at FROM approval_requests WHERE requester_id=? ORDER BY created_at DESC LIMIT 100", principal(ctx))
		if e != nil {
			return nil, nil, e
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, a, t, st, c, x string
			if rows.Scan(&id, &a, &t, &st, &c, &x) == nil {
				out = append(out, map[string]any{"request_id": id, "action_type": a, "target_id": t, "status": st, "created_at": c, "expires_at": x})
			}
		}
		return nil, map[string]any{"requests": out}, rows.Err()
	})
	mcp.AddTool[ID, map[string]any](server, &mcp.Tool{Name: "approval_get_audit", Description: "Get redacted audit events for a request.", InputSchema: objectSchema([]string{"request_id"})}, func(ctx context.Context, _ *mcp.CallToolRequest, in ID) (*mcp.CallToolResult, map[string]any, error) {
		var count int
		_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM approval_requests WHERE id=? AND requester_id=?", in.RequestID, principal(ctx)).Scan(&count)
		if count == 0 {
			return nil, map[string]any{"error": "request not found"}, nil
		}
		rows, e := s.db.QueryContext(ctx, "SELECT actor_id,actor_type,event_type,created_at FROM audit_events WHERE request_id=? ORDER BY id", in.RequestID)
		if e != nil {
			return nil, nil, e
		}
		defer rows.Close()
		events := []map[string]any{}
		for rows.Next() {
			var a, t, e, c string
			if rows.Scan(&a, &t, &e, &c) == nil {
				events = append(events, map[string]any{"actor_id": a, "actor_type": t, "event_type": e, "created_at": c})
			}
		}
		return nil, map[string]any{"events": events}, rows.Err()
	})
}
func (s *Service) create(ctx context.Context, in RequestInput) (map[string]any, error) {
	if in.ActionType == "" || in.TargetID == "" || in.ExecutorID == "" || in.Reason == "" || in.IdempotencyKey == "" || len(in.Action) == 0 {
		return nil, errors.New("missing required proposal fields")
	}
	if len(in.IdempotencyKey) > 128 || len(in.Reason) > 2048 || len(in.ActionType) > 128 || len(in.TargetID) > 128 || len(in.ExecutorID) > 128 {
		return nil, errors.New("proposal field exceeds size limit")
	}
	var registered int
	if s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM executors WHERE id=? AND enabled=1", in.ExecutorID).Scan(&registered) != nil || registered == 0 {
		return nil, errors.New("executor is not registered")
	}
	if containsSecret(in.Action) || secretValuePattern.MatchString(in.Reason) {
		return nil, errors.New("action or reason contains a field or value that may be a secret")
	}
	requesterID := principal(ctx)
	var identity string
	if s.db.QueryRowContext(ctx, "SELECT identity FROM requesters WHERE id=? AND enabled=1", requesterID).Scan(&identity) != nil {
		return nil, errors.New("requester is disabled")
	}
	var selected *Policy
	for i := range s.policies.Policies {
		p := &s.policies.Policies[i]
		if p.Deny && policyMatches(*p, in, identity) {
			return nil, errors.New("policy denied action")
		}
	}
	for i := range s.policies.Policies {
		p := &s.policies.Policies[i]
		if !p.Deny && policyMatches(*p, in, identity) {
			selected = p
			break
		}
	}
	if selected == nil {
		return nil, errors.New("no approval policy matched; default deny")
	}
	spec := map[string]any{"version": 1, "action_type": in.ActionType, "executor_id": in.ExecutorID, "target_id": in.TargetID, "required_execution_role": selected.RequiredRole, "parameters": in.Action}
	b, e := json.Marshal(spec)
	if e != nil {
		return nil, e
	}
	if len(b) > 7000 {
		return nil, errors.New("action specification is too large for a complete approval notification")
	}
	if requesterID == "" {
		return nil, errors.New("authenticated requester missing")
	}
	ttl := selected.TTLSeconds
	if in.Timeout > 0 && in.Timeout < ttl {
		ttl = in.Timeout
	}
	if ttl <= 0 || ttl > 86400 {
		ttl = 120
	}
	created := time.Now().UTC()
	expiry := created.Add(time.Duration(ttl) * time.Second)
	expiresAt := expiry.Format(time.RFC3339Nano)
	var existing string
	var oldDigest, oldStatus, oldExpiry string
	if s.db.QueryRowContext(ctx, `SELECT id,digest,status,expires_at FROM approval_requests WHERE requester_id=? AND idempotency_key=?`, requesterID, in.IdempotencyKey).Scan(&existing, &oldDigest, &oldStatus, &oldExpiry) == nil {
		if oldDigest != proposalDigest(requesterID, identity, selected, s.policies.Version, oldExpiry, in, b) {
			return nil, errors.New("idempotency key already used for a different proposal")
		}
		return map[string]any{"request_id": existing, "action_digest": oldDigest, "status": oldStatus, "expires_at": oldExpiry}, nil
	}
	digest := proposalDigest(requesterID, identity, selected, s.policies.Version, expiresAt, in, b)
	id := randomID()
	allowed, _ := json.Marshal(selected.AllowedApprovers)
	_, e = s.db.ExecContext(ctx, `INSERT INTO approval_requests(id,requester_id,executor_id,target_id,action_type,specification,digest,policy_version,risk,reason,status,minimum_approvers,allowed_approvers,created_at,expires_at,updated_at,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, requesterID, in.ExecutorID, in.TargetID, in.ActionType, string(b), digest, s.policies.Version, selected.Risk, in.Reason, "PENDING", max(1, selected.MinimumApprovers), string(allowed), created.Format(time.RFC3339Nano), expiry.Format(time.RFC3339Nano), created.Format(time.RFC3339Nano), in.IdempotencyKey)
	if e != nil {
		return nil, fmt.Errorf("proposal persistence failed: %w", e)
	}
	s.audit(ctx, id, requesterID, "requester", "request_created", map[string]any{"action_type": in.ActionType, "target_id": in.TargetID, "executor_id": in.ExecutorID, "digest": digest})
	if s.cfg.TelegramToken != "" {
		select {
		case s.notifications <- notification{id: id, input: in, spec: string(b), risk: selected.Risk, expiry: expiry}:
		default:
			s.audit(ctx, id, "telegram", "system", "notification_queue_full", map[string]any{"delivery": "failed"})
		}
	}
	return map[string]any{"request_id": id, "status": "PENDING", "action_digest": digest, "expires_at": expiry.Format(time.RFC3339Nano)}, nil
}
func (s *Service) status(ctx context.Context, requesterID, id string) map[string]any {
	var action, target, status, created, expires, risk string
	e := s.db.QueryRowContext(ctx, "SELECT action_type,target_id,status,created_at,expires_at,risk FROM approval_requests WHERE id=? AND requester_id=?", id, requesterID).Scan(&action, &target, &status, &created, &expires, &risk)
	if e != nil {
		return map[string]any{"error": "request not found"}
	}
	return map[string]any{"request_id": id, "action_type": action, "target_id": target, "status": status, "risk": risk, "created_at": created, "expires_at": expires}
}
func (s *Service) audit(ctx context.Context, id, actor, kind, event string, data any) {
	b, _ := json.Marshal(data)
	_, _ = s.db.ExecContext(ctx, `INSERT INTO audit_events(request_id,actor_id,actor_type,event_type,event_json,created_at) VALUES(?,?,?,?,?,?)`, nullEmpty(id), actor, kind, event, string(b), now())
}
func (s *Service) auditTx(ctx context.Context, tx *sql.Tx, id, actor, kind, event string, data any) {
	b, _ := json.Marshal(data)
	_, _ = tx.ExecContext(ctx, `INSERT INTO audit_events(request_id,actor_id,actor_type,event_type,event_json,created_at) VALUES(?,?,?,?,?,?)`, id, actor, kind, event, string(b), now())
}
func (s *Service) expirer(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rows, e := s.db.QueryContext(ctx, `SELECT id FROM approval_requests WHERE status='PENDING' AND expires_at<? LIMIT 256`, now())
			if e != nil {
				continue
			}
			var expired []string
			for rows.Next() {
				var id string
				if rows.Scan(&id) == nil {
					expired = append(expired, id)
				}
			}
			rows.Close()
			for _, id := range expired {
				res, e := s.db.ExecContext(ctx, `UPDATE approval_requests SET status='EXPIRED',updated_at=? WHERE id=? AND status='PENDING'`, now(), id)
				if e == nil {
					if n, _ := res.RowsAffected(); n == 1 {
						s.audit(ctx, id, "system", "system", "request_expired", map[string]any{})
					}
				}
			}
		}
	}
}
func (s *Service) telegramLoop(ctx context.Context) {
	offset := int64(0)
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?timeout=30&offset=%d", s.cfg.TelegramToken, offset)
		req, cancel := context.WithTimeout(ctx, 35*time.Second)
		r, e := http.NewRequestWithContext(req, "GET", url, nil)
		if e == nil {
			resp, er := http.DefaultClient.Do(r)
			if er == nil {
				var body struct {
					OK     bool `json:"ok"`
					Result []struct {
						UpdateID int64 `json:"update_id"`
						Callback *struct {
							ID, Data string
							From     struct {
								ID int64 `json:"id"`
							} `json:"from"`
							Message struct {
								Chat struct {
									ID int64 `json:"id"`
								} `json:"chat"`
							} `json:"message"`
						} `json:"callback_query"`
					}
				}
				if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body) == nil && body.OK {
					backoff = time.Second
					for _, u := range body.Result {
						offset = u.UpdateID + 1
						if u.Callback != nil {
							s.decision(u.Callback.From.ID, u.Callback.Message.Chat.ID, u.Callback.Data, u.Callback.ID)
						}
					}
				}
				resp.Body.Close()
			}
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}
func (s *Service) notify(id string, in RequestInput, spec, risk string, expiry time.Time) {
	text := fmt.Sprintf("Approval request %s\nAction: %s\nTarget: %s\nExecutor: %s\nRisk: %s\nReason: %s\nSpecification: %s\nExpires: %s", id, in.ActionType, in.TargetID, in.ExecutorID, risk, in.Reason, spec, expiry.Format(time.RFC3339))
	approve, reject := randomToken(), randomToken()
	deadline := expiry.Format(time.RFC3339Nano)
	_, _ = s.db.Exec(`INSERT INTO telegram_callbacks(token,request_id,decision,expires_at) VALUES(?,?,?,?),(?,?,?,?)`, approve, id, "APPROVE", deadline, reject, id, "REJECT", deadline)
	delivered := len(s.cfg.TelegramChats) > 0
	for chat := range s.cfg.TelegramChats {
		if !s.telegram("sendMessage", map[string]any{"chat_id": chat, "text": text, "reply_markup": map[string]any{"inline_keyboard": [][]map[string]string{{{"text": "Approve", "callback_data": "a:" + id + ":" + approve}, {"text": "Reject", "callback_data": "r:" + id + ":" + reject}}}}}) {
			delivered = false
		}
	}
	if delivered {
		s.audit(context.Background(), id, "telegram", "system", "notification_sent", map[string]any{})
	} else {
		s.audit(context.Background(), id, "telegram", "system", "notification_failed", map[string]any{"delivery": "failed"})
		s.logger.Error("telegram notification failed", "request_id", id)
	}
}
func (s *Service) notificationWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case n := <-s.notifications:
			s.notify(n.id, n.input, n.spec, n.risk, n.expiry)
		}
	}
}
func (s *Service) decision(user, chat int64, data, callback string) {
	parts := strings.Split(data, ":")
	if len(parts) != 3 || !s.cfg.TelegramUsers[user] || !s.cfg.TelegramChats[chat] {
		return
	}
	verb, id, token := parts[0], parts[1], parts[2]
	decision := "APPROVE"
	if verb == "r" {
		decision = "REJECT"
	}
	if (verb != "a" && verb != "r") || len(token) != 28 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var approver int64
	var role string
	if s.db.QueryRowContext(ctx, "SELECT id,role FROM approvers WHERE telegram_user_id=? AND enabled=1", user).Scan(&approver, &role) != nil {
		return
	}
	var requester, status string
	var exp string
	if s.db.QueryRowContext(ctx, "SELECT requester_id,status,expires_at FROM approval_requests WHERE id=?", id).Scan(&requester, &status, &exp) != nil || status != "PENDING" {
		return
	}
	var min int
	var allowed string
	if s.db.QueryRowContext(ctx, "SELECT minimum_approvers,allowed_approvers FROM approval_requests WHERE id=?", id).Scan(&min, &allowed) != nil {
		return
	}
	if time.Now().After(mustTime(exp)) {
		_, _ = s.db.ExecContext(ctx, "UPDATE approval_requests SET status='EXPIRED',updated_at=? WHERE id=? AND status='PENDING'", now(), id)
		return
	}
	var allowIDs []int64
	_ = json.Unmarshal([]byte(allowed), &allowIDs)
	if len(allowIDs) > 0 {
		found := false
		for _, v := range allowIDs {
			if v == user {
				found = true
			}
		}
		if !found {
			return
		}
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return
	}
	defer tx.Rollback()
	var current string
	var currentExpiry string
	if tx.QueryRowContext(ctx, "SELECT status,expires_at FROM approval_requests WHERE id=?", id).Scan(&current, &currentExpiry) != nil || current != "PENDING" {
		return
	}
	if time.Now().After(mustTime(currentExpiry)) {
		_, _ = tx.ExecContext(ctx, "UPDATE approval_requests SET status='EXPIRED',updated_at=? WHERE id=? AND status='PENDING'", now(), id)
		_ = tx.Commit()
		return
	}
	var requesterIdentity string
	_ = tx.QueryRowContext(ctx, "SELECT identity FROM requesters WHERE id=?", requester).Scan(&requesterIdentity)
	if requesterIdentity == strconv.FormatInt(user, 10) {
		return
	}
	var callbackRequest, callbackDecision, callbackExpiry string
	if tx.QueryRowContext(ctx, "SELECT request_id,decision,expires_at FROM telegram_callbacks WHERE token=? AND used_at IS NULL", token).Scan(&callbackRequest, &callbackDecision, &callbackExpiry) != nil || callbackRequest != id || callbackDecision != decision || time.Now().After(mustTime(callbackExpiry)) {
		return
	}
	_, e = tx.ExecContext(ctx, "UPDATE telegram_callbacks SET used_at=? WHERE token=? AND used_at IS NULL", now(), token)
	if e != nil {
		return
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO approval_decisions(request_id,approver_id,decision,decided_at) VALUES(?,?,?,?)", id, approver, decision, now())
	if e != nil {
		return
	}
	next := "PENDING"
	if decision == "REJECT" {
		next = "REJECTED"
	} else {
		var count int
		_ = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM approval_decisions WHERE request_id=? AND decision='APPROVE'", id).Scan(&count)
		if count >= min {
			next = "APPROVED"
		}
	}
	update, e := tx.ExecContext(ctx, "UPDATE approval_requests SET status=?,updated_at=? WHERE id=? AND status='PENDING'", next, now(), id)
	if e != nil {
		return
	}
	if n, _ := update.RowsAffected(); n != 1 {
		return
	}
	s.auditTx(ctx, tx, id, strconv.FormatInt(user, 10), "approver", "decision_"+strings.ToLower(decision), map[string]any{"status": next})
	if tx.Commit() != nil {
		return
	}
	s.telegram("answerCallbackQuery", map[string]any{"callback_query_id": callback, "text": "Decision recorded"})
}
func (s *Service) telegram(method string, payload any) bool {
	b, _ := json.Marshal(payload)
	req, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, e := http.NewRequestWithContext(req, "POST", "https://api.telegram.org/bot"+s.cfg.TelegramToken+"/"+method, strings.NewReader(string(b)))
	if e != nil {
		return false
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := http.DefaultClient.Do(r)
	if e != nil {
		return false
	}
	defer resp.Body.Close()
	var result struct {
		OK bool `json:"ok"`
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result) == nil && resp.StatusCode == http.StatusOK && result.OK
}
func loadPolicies(path string) (PolicyFile, error) {
	var p PolicyFile
	b, e := os.ReadFile(path)
	if e != nil {
		return p, e
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(b)))
	decoder.KnownFields(true)
	if e = decoder.Decode(&p); e != nil {
		return p, e
	}
	if p.Version == "" || len(p.Policies) == 0 {
		return p, errors.New("policy file requires a version and at least one policy")
	}
	for _, rule := range p.Policies {
		if rule.ID == "" || rule.ActionType == "" || rule.Target == "" || rule.Executor == "" {
			return p, errors.New("policy entries require id, action_type, target, and executor")
		}
		switch strings.ToUpper(rule.Risk) {
		case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		default:
			return p, fmt.Errorf("policy %s has invalid risk", rule.ID)
		}
		if !rule.Deny && rule.MinimumApprovers < 1 {
			return p, fmt.Errorf("policy %s must require at least one approver", rule.ID)
		}
		if !rule.Deny && (rule.TTLSeconds < 1 || rule.TTLSeconds > 86400) {
			return p, fmt.Errorf("policy %s has invalid ttl_seconds", rule.ID)
		}
	}
	return p, nil
}
func policyMatches(p Policy, in RequestInput, requester string) bool {
	return (p.ActionType == "*" || p.ActionType == in.ActionType) && (p.Target == "*" || p.Target == in.TargetID) && (p.Executor == "*" || p.Executor == in.ExecutorID) && (p.Requester == "*" || p.Requester == "" || p.Requester == requester)
}
func proposalDigest(requesterID, identity string, p *Policy, version, expiry string, in RequestInput, spec []byte) string {
	allowed, _ := json.Marshal(p.AllowedApprovers)
	binding := struct {
		RequesterID       string          `json:"requester_id"`
		RequesterIdentity string          `json:"requester_identity"`
		ExecutorID        string          `json:"executor_id"`
		TargetID          string          `json:"target_id"`
		ActionType        string          `json:"action_type"`
		Specification     json.RawMessage `json:"specification"`
		RequiredRole      string          `json:"required_execution_role"`
		PolicyVersion     string          `json:"policy_version"`
		Risk              string          `json:"risk"`
		Reason            string          `json:"reason"`
		MinimumApprovers  int             `json:"minimum_approvers"`
		AllowedApprovers  json.RawMessage `json:"allowed_approvers"`
		ExpiresAt         string          `json:"expires_at"`
	}{requesterID, identity, in.ExecutorID, in.TargetID, in.ActionType, spec, p.RequiredRole, version, p.Risk, in.Reason, max(1, p.MinimumApprovers), allowed, expiry}
	b, _ := json.Marshal(binding)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var secretValuePattern = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key|private[_-]?key|authorization|bearer)[\s=:]+[^\s,;]+`)

func containsSecret(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if secretValuePattern.MatchString(k) || strings.Contains(strings.ToLower(k), "credential") {
				return true
			}
			if containsSecret(val) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if containsSecret(val) {
				return true
			}
		}
	case string:
		if secretValuePattern.MatchString(x) {
			return true
		}
	}
	return false
}
func principal(ctx context.Context) string { v, _ := ctx.Value(requesterKey{}).(string); return v }
func tokenHash(v string) string            { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func nullEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func mustTime(v string) time.Time { t, _ := time.Parse(time.RFC3339Nano, v); return t }
func objectSchema(required []string) map[string]any {
	p := map[string]any{"action_type": map[string]any{"type": "string"}, "target_id": map[string]any{"type": "string"}, "executor_id": map[string]any{"type": "string"}, "action_specification": map[string]any{"type": "object"}, "reason": map[string]any{"type": "string"}, "requested_timeout": map[string]any{"type": "integer"}, "idempotency_key": map[string]any{"type": "string"}, "request_id": map[string]any{"type": "string"}}
	return map[string]any{"type": "object", "properties": p, "required": required, "additionalProperties": false}
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		http.Error(w, "invalid request", 400)
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func secureEqual(a, b string) bool {
	if len(a) != len(b) || a == "" {
		return false
	}
	return subtleEqual(a, b)
}
func subtleEqual(a, b string) bool     { return len(a) == len(b) && constantCompare(a, b) }
func constantCompare(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func now() string                      { return time.Now().UTC().Format(time.RFC3339Nano) }
func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return strings.ToUpper(hex.EncodeToString(b[:]))
}
func randomToken() string { var b [14]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }
func ids(v string) map[int64]bool {
	out := map[int64]bool{}
	for _, s := range strings.Split(v, ",") {
		if n, e := strconv.ParseInt(strings.TrimSpace(s), 10, 64); e == nil && n != 0 {
			out[n] = true
		}
	}
	return out
}
func pathExecutor(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}
func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
func secretEnv(key string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	path := strings.TrimSpace(os.Getenv(key + "_FILE"))
	if path == "" {
		return ""
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
