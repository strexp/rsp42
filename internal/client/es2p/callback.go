package es2p

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"rsp42/internal/metrics"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// CallbackQueue delivers ES2+ HandleDownloadProgressInfo notifications reliably:
// each notification is persisted before the first delivery attempt and retried
// from the database until it succeeds or the attempt budget is exhausted (then
// it becomes a dead letter). It satisfies the service.OperatorCallback
// signature and can be wired directly into the notification/download services.
// QueueOptions are the tunables of the durable callback queue. The zero value
// selects the production defaults (five attempts, batches of 20, exponential
// backoff, the wall clock), so a caller only sets what it wants to override;
// tests use it to make retries immediate and deterministic.
type QueueOptions struct {
	// URLForTenant, when set, overrides the delivery URL for a tenant; an empty
	// return falls back to Client.URL.
	URLForTenant func(tenant string) string
	// Metrics, when set, counts delivery outcomes by tenant/point/status.
	Metrics     *metrics.Registry
	MaxAttempts int
	Batch       int
	Backoff     func(attempt int) time.Duration
	Log         *slog.Logger
	Now         func() time.Time
}

// QueueStore is the persistence the durable callback queue needs. It is defined
// by the consumer so the SQLite repository stays a detail; *store.CallbackRepo
// satisfies it.
type QueueStore interface {
	Enqueue(url, payload string, pointID int) (int64, error)
	Get(id int64) (*store.Callback, error)
	Due(now time.Time, limit int) ([]*store.Callback, error)
	MarkSent(id int64, response string) error
	MarkFailed(id int64, response string) error
	MarkRetry(id int64, next time.Time, response string) error
}

type CallbackQueue struct {
	Repo   QueueStore
	Client *CallbackClient
	QueueOptions
}

// The SQLite repository must keep satisfying the seam.
var _ QueueStore = (*store.CallbackRepo)(nil)

// NewCallbackQueue builds a queue with sane defaults.
func NewCallbackQueue(repo QueueStore, client *CallbackClient, opts QueueOptions) *CallbackQueue {
	if opts.MaxAttempts < 1 {
		opts.MaxAttempts = 5
	}
	if opts.Batch < 1 {
		opts.Batch = 20
	}
	if opts.Backoff == nil {
		opts.Backoff = func(attempt int) time.Duration { return time.Duration(1<<uint(attempt)) * time.Second }
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	return &CallbackQueue{Repo: repo, Client: client, QueueOptions: opts}
}

// Deliver persists a progress notification and attempts immediate delivery.
// A failed immediate attempt leaves a pending row that RunOnce will retry.
func (q *CallbackQueue) Deliver(ctx context.Context, info service.ProgressInfo) error {
	if q.Metrics != nil {
		// Counted once per notification (not once per delivery attempt: retries
		// go through attempt(), which does not increment). The name matches what
		// esim42's dashboards read; see internal/service/metrics.go.
		q.Metrics.Inc("rsp42_downloads_total", map[string]string{
			"tenant": info.TenantID,
			"point":  fmt.Sprintf("%d", info.NotificationPointID),
			"status": info.NotificationPointStatus.Status,
		})
	}
	url := q.urlFor(info.TenantID)
	if url == "" {
		return fmt.Errorf("es2plus: no callback URL configured")
	}
	payload, err := q.encode(info)
	if err != nil {
		return err
	}
	id, err := q.Repo.Enqueue(url, string(payload), info.NotificationPointID)
	if err != nil {
		return err
	}
	return q.attempt(ctx, id, url, payload)
}

// urlFor resolves the delivery URL for a tenant (per-tenant override, else the
// global callback URL).
func (q *CallbackQueue) urlFor(tenant string) string {
	if q.URLForTenant != nil && tenant != "" {
		if u := q.URLForTenant(tenant); u != "" {
			return u
		}
	}
	if q.Client == nil {
		return ""
	}
	return q.Client.URL
}

// RunOnce delivers due pending notifications and returns how many were
// attempted.
func (q *CallbackQueue) RunOnce(ctx context.Context) (int, error) {
	due, err := q.Repo.Due(q.Now(), q.Batch)
	if err != nil {
		return 0, err
	}
	for _, cb := range due {
		_ = q.attempt(ctx, cb.ID, cb.URL, []byte(cb.Payload))
	}
	return len(due), nil
}

// Run processes due notifications every interval until ctx is done.
func (q *CallbackQueue) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := q.RunOnce(ctx); err != nil && q.Log != nil {
				q.Log.Warn("callback retry sweep", "err", err)
			}
		}
	}
}

// encode fills the transport-owned fields of a notification and serializes the
// single shared DTO (service.ProgressInfo). Callers must have set the domain
// fields; Header and Timestamp are always regenerated here.
func (q *CallbackQueue) encode(info service.ProgressInfo) ([]byte, error) {
	info.Header = map[string]string{
		"functionRequesterIdentifier": q.Client.RequesterID,
		"functionCallIdentifier":      fmt.Sprintf("CB-%d", q.Now().UnixNano()),
	}
	info.Timestamp = q.Now().Format(time.RFC3339)
	return json.Marshal(info)
}

func (q *CallbackQueue) attempt(ctx context.Context, id int64, url string, payload []byte) error {
	err := q.Client.Post(ctx, url, payload)
	if err == nil {
		if mErr := q.Repo.MarkSent(id, ""); mErr != nil && q.Log != nil {
			q.Log.Warn("callback mark sent", "id", id, "err", mErr)
		}
		return nil
	}

	// Determine how many attempts have already been recorded.
	prior := 0
	if cb, gErr := q.Repo.Get(id); gErr == nil {
		prior = cb.Attempts
	}
	attempts := prior + 1
	if q.MaxAttempts > 0 && attempts >= q.MaxAttempts {
		_ = q.Repo.MarkFailed(id, err.Error())
		if q.Log != nil {
			q.Log.Error("operator callback dead-lettered", "id", id, "attempts", attempts, "err", err)
		}
		return err
	}
	next := q.Now().Add(q.Backoff(attempts))
	_ = q.Repo.MarkRetry(id, next, err.Error())
	if q.Log != nil {
		q.Log.Warn("operator callback failed; retry scheduled", "id", id, "attempts", attempts, "next", next, "err", err)
	}
	return err
}
