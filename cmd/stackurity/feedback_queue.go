package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/feedback"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/worker"
)

// Retention of the feedback queue (docs/feedback-queue.md): attachment
// files 180 days after an item closes, records two years after.
const (
	feedbackAttachmentRetention = 180 * 24 * time.Hour
	feedbackRecordRetention     = 2 * 365 * 24 * time.Hour
)

// feedbackQueueFromEnv turns the feedback queue on when
// STACKURITY_FEEDBACK_QUEUE_DIR is set (only the Stackurity team's server).
func feedbackQueueFromEnv(log *slog.Logger) (*api.FeedbackQueue, error) {
	dir := strings.TrimSpace(os.Getenv("STACKURITY_FEEDBACK_QUEUE_DIR"))
	if dir == "" {
		return nil, nil
	}
	key := os.Getenv("STACKURITY_FEEDBACK_INTAKE_KEY")
	if f := os.Getenv("STACKURITY_FEEDBACK_INTAKE_KEY_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("STACKURITY_FEEDBACK_INTAKE_KEY_FILE: %w", err)
		}
		key = strings.TrimSpace(string(b))
	}
	if len(key) < 32 {
		return nil, errors.New("STACKURITY_FEEDBACK_QUEUE_DIR needs STACKURITY_FEEDBACK_INTAKE_KEY (or _FILE) of at least 32 characters")
	}
	maxMB := int64(5120)
	if v := strings.TrimSpace(os.Getenv("STACKURITY_FEEDBACK_STORAGE_MAX_MB")); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("STACKURITY_FEEDBACK_STORAGE_MAX_MB must be a positive number of megabytes, not %q", v)
		}
		maxMB = n
	}
	disk, err := feedback.OpenDisk(dir)
	if err != nil {
		return nil, fmt.Errorf("STACKURITY_FEEDBACK_QUEUE_DIR: %w", err)
	}
	if err := disk.RemoveStale(); err != nil {
		log.Warn("feedback queue: could not remove unfinished uploads", "err", err)
	}
	log.Info("feedback queue enabled", "dir", dir, "storage_max_mb", maxMB)
	return &api.FeedbackQueue{Disk: disk, IntakeKey: key, StorageMax: maxMB << 20}, nil
}

// registerFeedbackRetention deletes old attachment files and records daily.
func registerFeedbackRetention(w *worker.Worker, st *store.Store, q *api.FeedbackQueue, log *slog.Logger) {
	if q == nil {
		return
	}
	w.Every("feedback-retention", 24*time.Hour, func(ctx context.Context) error {
		files, items, err := st.PurgeFeedback(ctx, feedbackAttachmentRetention, feedbackRecordRetention, q.Disk.Remove)
		if files > 0 || items > 0 {
			log.Info("feedback retention", "files_deleted", files, "items_deleted", items)
		}
		return err
	})
}
