package es2plus

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"rsp42/internal/store"
)

// CallbackQueue delivers ES2+ HandleDownloadProgressInfo notifications reliably:
// each notification is persisted before the first delivery attempt and retried
// from the database until it succeeds or the attempt budget is exhausted (then
// it becomes a dead letter). It satisfies the service.OperatorCallback
// signature and can be wired directly into the notification/download services.
type CallbackQueue struct {
	Repo        *store.CallbackRepo
	Client      *CallbackClient
	MaxAttempts int
	Batch       int
	Backoff     func(attempt int) time.Duration
	Log         *slog.Logger
	Now         func() time.Time
}

// NewCallbackQueue builds a queue with sane defaults.
func NewCallbackQueue(repo *store.CallbackRepo, client *CallbackClient, log *slog.Logger) *CallbackQueue {
	return &CallbackQueue{
		Repo:        repo,
		Client:      client,
		MaxAttempts: 5,
		Batch:       20,
		Backoff:     func(attempt int) time.Duration { return time.Duration(1<<uint(attempt)) * time.Second },
		Log:         log,
		Now:         func() time.Time { return time.Now().UTC() },
	}
}

// Deliver persists a progress notification and attempts immediate delivery.
// A failed immediate attempt leaves a pending row that RunOnce will retry.
func (q *CallbackQueue) Deliver(ctx context.Context, eid, iccid string, pointID int, status string) error {
	if q.Client == nil || q.Client.URL == "" {
		return fmt.Errorf("es2plus: no callback URL configured")
	}
	payload, err := q.encode(eid, iccid, pointID, status)
	if err != nil {
		return err
	}
	id, err := q.Repo.Enqueue(q.Client.URL, string(payload), pointID)
	if err != nil {
		return err
	}
	return q.attempt(ctx, id, q.Client.URL, payload)
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

func (q *CallbackQueue) encode(eid, iccid string, pointID int, status string) ([]byte, error) {
	return json.Marshal(ProgressInfo{
		Header: map[string]string{
			"functionRequesterIdentifier": q.Client.RequesterID,
			"functionCallIdentifier":      fmt.Sprintf("CB-%d", q.Now().UnixNano()),
		},
		EID:                     eid,
		ICCID:                   iccid,
		Timestamp:               q.Now().Format(time.RFC3339),
		NotificationPointID:     pointID,
		NotificationPointStatus: map[string]any{"status": status},
	})
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
