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
	linkKey := os.Getenv("STACKURITY_FEEDBACK_LINK_KEY")
	if f := os.Getenv("STACKURITY_FEEDBACK_LINK_KEY_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("STACKURITY_FEEDBACK_LINK_KEY_FILE: %w", err)
		}
		linkKey = strings.TrimSpace(string(b))
	}
	if linkKey != "" && (len(linkKey) < 32 || linkKey == key) {
		return nil, errors.New("STACKURITY_FEEDBACK_LINK_KEY must be at least 32 characters and differ from the intake key")
	}
	return &api.FeedbackQueue{Disk: disk, IntakeKey: key, StorageMax: maxMB << 20, LinkKey: linkKey}, nil
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
		if err != nil {
			return err
		}
		// Files with no row: a crash between writing a file and storing
		// its item. An hour is far longer than any upload takes.
		onDisk, err := q.Disk.Keys(time.Now().Add(-time.Hour))
		if err != nil {
			return err
		}
		known, err := st.FeedbackStorageKeys(ctx)
		if err != nil {
			return err
		}
		for _, k := range onDisk {
			if !known[k] {
				if err := q.Disk.Remove(k); err != nil {
					return err
				}
				log.Warn("feedback: removed an attachment file with no item", "key", k)
			}
		}
		return nil
	})
}
