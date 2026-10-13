// Package approvalclient implements the requester and executor HTTP interfaces.
package approvalclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL, RequesterToken, ExecutorToken, ExecutorID string
	HTTP                                               *http.Client
}
type Proposal struct {
	ActionType     string         `json:"action_type"`
	TargetID       string         `json:"target_id"`
	ExecutorID     string         `json:"executor_id"`
	Action         map[string]any `json:"action_specification"`
	Reason         string         `json:"reason"`
	Timeout        int            `json:"requested_timeout,omitempty"`
	IdempotencyKey string         `json:"idempotency_key"`
}
type Authorization struct {
	RequestID     string          `json:"request_id"`
	ExecutorID    string          `json:"executor_id"`
	ActionDigest  string          `json:"action_digest"`
	Specification json.RawMessage `json:"action_specification"`
	Status        string          `json:"status"`
}
type ExecutionReport struct {
	RequestID       string `json:"request_id"`
	ExecutionID     string `json:"execution_id"`
	Outcome         string `json:"outcome"`
	StartedAt       string `json:"started_at,omitempty"`
	FinishedAt      string `json:"finished_at,omitempty"`
	ResultReference string `json:"result_reference,omitempty"`
	ErrorSummary    string `json:"error_summary,omitempty"`
}
type Status struct {
	RequestID  string `json:"request_id"`
	ActionType string `json:"action_type"`
	TargetID   string `json:"target_id"`
	State      string `json:"status"`
	Risk       string `json:"risk"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}
func (c *Client) ProposeAction(ctx context.Context, p Proposal) (map[string]any, error) {
	var result map[string]any
	e := c.do(ctx, http.MethodPost, "/v1/requests", p, c.RequesterToken, &result)
	return result, e
}
func (c *Client) GetApprovalStatus(ctx context.Context, requestID string) (Status, error) {
	var result Status
	e := c.do(ctx, http.MethodGet, "/v1/requests/"+url.PathEscape(requestID), nil, c.RequesterToken, &result)
	return result, e
}
func (c *Client) ClaimApprovedAction(ctx context.Context, requestID, digest string) (Authorization, error) {
	if c.ExecutorID == "" {
		return Authorization{}, errors.New("executor ID is required")
	}
	attempt, e := random()
	if e != nil {
		return Authorization{}, e
	}
	input := map[string]string{"request_id": requestID, "expected_action_digest": digest, "claim_attempt_id": attempt}
	var result Authorization
	e = c.do(ctx, http.MethodPost, "/v1/executors/"+url.PathEscape(c.ExecutorID)+"/claim", input, c.ExecutorToken, &result)
	return result, e
}
func (c *Client) ReportExecutionOutcome(ctx context.Context, r ExecutionReport) error {
	if c.ExecutorID == "" {
		return errors.New("executor ID is required")
	}
	return c.do(ctx, http.MethodPost, "/v1/executors/"+url.PathEscape(c.ExecutorID)+"/result", r, c.ExecutorToken, nil)
}

// ExecuteAuthorizedAction claims once and invokes execute only with the stored envelope.
// Any returned execution error is conservatively reported as INDETERMINATE.
func (c *Client) ExecuteAuthorizedAction(ctx context.Context, requestID, digest string, execute func(context.Context, json.RawMessage) (ExecutionReport, error)) (ExecutionReport, error) {
	auth, e := c.ClaimApprovedAction(ctx, requestID, digest)
	if e != nil {
		return ExecutionReport{}, e
	}
	if auth.Status != "CLAIMED" || auth.RequestID != requestID || auth.ExecutorID != c.ExecutorID || auth.ActionDigest != digest || len(auth.Specification) == 0 {
		return ExecutionReport{}, errors.New("invalid authorization response")
	}
	started := time.Now().UTC()
	report := ExecutionReport{RequestID: requestID, StartedAt: started.Format(time.RFC3339Nano)}
	report.ExecutionID, e = random()
	if e != nil {
		return report, e
	}
	report.Outcome = "EXECUTING"
	if e = c.ReportExecutionOutcome(ctx, report); e != nil {
		return report, fmt.Errorf("could not record execution start; action was not run: %w", e)
	}
	executionID := report.ExecutionID
	report, e = execute(ctx, auth.Specification)
	report.RequestID = requestID
	report.ExecutionID = executionID
	report.StartedAt = started.Format(time.RFC3339Nano)
	if e != nil {
		report.Outcome = "INDETERMINATE"
		report.ErrorSummary = "executor returned an error; remote outcome may be uncertain"
	} else if report.Outcome == "" || report.Outcome == "EXECUTING" {
		report.Outcome = "SUCCEEDED"
	}
	if report.FinishedAt == "" {
		report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if re := c.ReportExecutionOutcome(ctx, report); re != nil {
		return report, fmt.Errorf("execution result reporting failed: %w", re)
	}
	return report, e
}

func (c *Client) do(ctx context.Context, method, path string, input any, token string, output any) error {
	if c.BaseURL == "" || token == "" {
		return errors.New("approval client is not configured")
	}
	var body io.Reader
	if input != nil {
		b, e := json.Marshal(input)
		if e != nil {
			return e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, body)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := c.httpClient().Do(req)
	if e != nil {
		return fmt.Errorf("approval service unavailable: %w", e)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("approval service returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if output == nil {
		return nil
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if e = d.Decode(output); e != nil {
		return fmt.Errorf("invalid approval response: %w", e)
	}
	return nil
}
func random() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}
func bounded(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
