//
// Copyright 2022 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package file

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/metrics"
)

const (
	FileCollector = "FileCollector"

	// FileReadErrorsCounter tracks files that could not be read.
	FileReadErrorsCounter = "file_read_errors"
)

var registerMetricsOnce sync.Once

type fileCollector struct {
	path        string
	lastChecked time.Time
	poll        bool
	interval    time.Duration
	Metrics     metrics.MetricCollector
}

type Opt func(*fileCollector)

// WithMetrics wires m into the collector. Call RegisterMetrics once first.
func WithMetrics(m metrics.MetricCollector) Opt {
	return func(f *fileCollector) {
		f.Metrics = m
	}
}

// RegisterMetrics is safe to call multiple times; it only registers once.
func RegisterMetrics(ctx context.Context, m metrics.MetricCollector) error {
	var err error
	registerMetricsOnce.Do(func() {
		if _, regErr := m.RegisterCounter(ctx, FileReadErrorsCounter); regErr != nil {
			err = fmt.Errorf("failed to register counter for file read errors: %w", regErr)
		}
	})
	return err
}

func NewFileCollector(ctx context.Context, path string, poll bool, interval time.Duration, opts ...Opt) *fileCollector {
	f := &fileCollector{
		path:     path,
		poll:     poll,
		interval: interval,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// RetrieveArtifacts collects the documents from the collector. It emits each collected
// document through the channel to be collected and processed by the upstream processor.
// The function should block until all the artifacts are collected and return a nil error
// or return an error from the collector crashing. This function can keep running and check
// for new artifacts as they are being uploaded by polling on an interval or run once and
// grab all the artifacts and end.
func (f *fileCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if _, err := os.Stat(f.path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("path: %s does not exist", f.path)
		}
		return fmt.Errorf("unknown error on os.Stat for FileCollector path: %w", err)
	}

	logger := logging.FromContext(ctx)

	readFunc := func(path string, dirEntry fs.DirEntry, err error) error {
		// If the context has been canceled it contains an err which we can throw.
		// When it gets thrown a second time will cancel the walk.
		// See filepath.WalkDir for more info.
		if ctx.Err() != nil {
			return ctx.Err() // nolint:wrapcheck
		}
		// NOTE: Explicitly rethrowing new errors if a particular directory has an error.
		// If we rethrow the error it kills the whole walk. Still useful to make it explicit that we ran into an error.
		if err != nil {
			// Inaccessible paths below the root (EACCES/EPERM) are skipped so one unreadable entry
			// does not abort a large ingestion.
			if errors.Is(err, fs.ErrPermission) && path != f.path {
				logger.Warnw("skipping inaccessible path", "path", path, "error", err)
				if dirEntry != nil && dirEntry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			return fmt.Errorf("path: %s is invalid", path)
		}
		if dirEntry.IsDir() {
			return nil
		}
		info, err := dirEntry.Info()
		if err != nil {
			if errors.Is(err, fs.ErrPermission) && path != f.path {
				logger.Warnw("skipping inaccessible file", "path", path, "error", err)
				return nil
			}
			return fmt.Errorf("unknown error on dirEntry.Info while walking path: %w", err)
		}
		if !info.ModTime().After(f.lastChecked) {
			return nil
		}

		blob, err := os.ReadFile(path)
		if err != nil {
			f.recordRetrievalError(ctx)
			if errors.Is(err, fs.ErrPermission) && path != f.path {
				logger.Warnw("skipping unreadable file", "path", path, "error", err)
				return nil
			}
			return fmt.Errorf("error reading file: %s, err: %w", path, err)
		}

		doc := &processor.Document{
			Blob:   blob,
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector:   string(FileCollector),
				Source:      fmt.Sprintf("file:///%s", path),
				DocumentRef: events.GetDocRef(blob),
			},
		}

		docChannel <- doc

		return nil
	}

	for {
		if err := filepath.WalkDir(f.path, readFunc); err != nil {
			return fmt.Errorf("error walking path: %s, err: %w", f.path, err)
		}
		f.lastChecked = time.Now()
		if !f.poll {
			break
		}
		select {
		// If the context has been canceled it contains an err which we can throw.
		case <-ctx.Done():
			return ctx.Err() // nolint:wrapcheck
		case <-time.After(f.interval):
		}
	}

	return nil
}

// Type returns the collector type
func (f *fileCollector) Type() string {
	return FileCollector
}

func (f *fileCollector) recordRetrievalError(ctx context.Context) {
	if f.Metrics == nil {
		return
	}
	if err := f.Metrics.AddCounter(ctx, FileReadErrorsCounter, 1); err != nil {
		logging.FromContext(ctx).Debugf("failed to record file read error metric: %v", err)
	}
}
