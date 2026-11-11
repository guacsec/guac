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
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func Test_fileCollector_RetrieveArtifacts(t *testing.T) {
	type fields struct {
		path        string
		lastChecked time.Time
		poll        bool
		interval    time.Duration
	}
	tests := []struct {
		name    string
		fields  fields
		want    []*processor.Document
		wantErr bool
	}{{
		name: "nonexistent file path",
		fields: fields{
			path:        "./doesnotexist",
			lastChecked: time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
			poll:        false,
			interval:    0,
		},
		want:    nil,
		wantErr: true,
	}, {
		name: "found file",
		fields: fields{
			path:        "./testdata",
			lastChecked: time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
			poll:        false,
			interval:    0,
		},
		want: []*processor.Document{{
			Blob:   []byte("hello\n"),
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector:   string(FileCollector),
				Source:      "file:///testdata/hello",
				DocumentRef: events.GetDocRef([]byte("hello\n")),
			}},
		},
		wantErr: false,
	}, {
		name: "with canceled poll",
		fields: fields{
			path:        "./testdata",
			lastChecked: time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
			poll:        true,
			interval:    time.Millisecond,
		},
		want: []*processor.Document{{
			Blob:   []byte("hello\n"),
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector:   string(FileCollector),
				Source:      "file:///testdata/hello",
				DocumentRef: events.GetDocRef([]byte("hello\n")),
			}},
		},
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fileCollector{
				path:        tt.fields.path,
				lastChecked: tt.fields.lastChecked,
				poll:        tt.fields.poll,
				interval:    tt.fields.interval,
			}
			// NOTE: Below is one of the simplest ways to validate the context getting canceled()
			// This is still brittle if a test for some reason takes longer than a second.
			// With that said, the tests are simple and this should only trigger to cancel polling.
			var ctx context.Context
			var cancel context.CancelFunc
			if f.poll {
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				defer cancel()
			} else {
				ctx = context.Background()
			}

			collector.DeregisterDocumentCollector(FileCollector)
			if err := collector.RegisterDocumentCollector(f, FileCollector); err != nil &&
				!errors.Is(err, collector.ErrCollectorOverwrite) {
				t.Fatalf("could not register collector: %v", err)
			}

			var s []*processor.Document
			em := func(d *processor.Document) error {
				s = append(s, d)
				return nil
			}
			eh := func(err error) bool {
				if (err != nil) != tt.wantErr {
					t.Errorf("fileCollector.RetrieveArtifacts() = %v, want %v", err, tt.wantErr)
				}
				return true
			}

			if err := collector.Collect(ctx, em, eh); err != nil {
				t.Fatalf("Collector error handler error: %v", err)
			}

			if !checkWhileIgnoringLogger(s, tt.want) {
				t.Errorf("fileCollector.RetrieveArtifacts() = %v, want %v", s, tt.want)
			}
			if f.Type() != FileCollector {
				t.Errorf("fileCollector.Type() = %s, want %s", f.Type(), FileCollector)
			}
		})
	}
}

// checkWhileIgnoringLogger works like a regular reflect.DeepEqual(), but ignores the loggers.
func checkWhileIgnoringLogger(collectedDoc, want []*processor.Document) bool {
	if len(collectedDoc) != len(want) {
		return false
	}

	for i := 0; i < len(collectedDoc); i++ {
		// Store the loggers, and then set the loggers to nil so that can ignore them.
		a, b := collectedDoc[i].ChildLogger, want[i].ChildLogger
		collectedDoc[i].ChildLogger, want[i].ChildLogger = nil, nil

		if !reflect.DeepEqual(collectedDoc[i], want[i]) {
			return false
		}

		// Re-assign the loggers so that they remain the same
		collectedDoc[i].ChildLogger, want[i].ChildLogger = a, b
	}

	return true
}

func TestRetrieveArtifacts_SkipsUnreadableEntries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions are not enforced the same way on windows")
	}

	root := t.TempDir()
	write := func(rel, content string) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	write("a.json", "a")
	write("sub/b.json", "b")
	unreadableFile := write("unreadable.json", "secret")
	unreadableDirFile := write("locked/c.json", "c")
	lockedDir := filepath.Dir(unreadableDirFile)

	if err := os.Chmod(unreadableFile, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockedDir, 0); err != nil {
		t.Fatal(err)
	}
	// Restore so t.TempDir cleanup can remove everything.
	t.Cleanup(func() {
		_ = os.Chmod(lockedDir, 0o755)
		_ = os.Chmod(unreadableFile, 0o644)
	})

	// Permissions are not enforced for root or some filesystems; skip then.
	if f, err := os.Open(unreadableFile); err == nil {
		_ = f.Close()
		t.Skip("permissions cannot be enforced in this environment")
	}

	fc := NewFileCollector(context.Background(), root, false, 0)
	docChan := make(chan *processor.Document, 10)

	if err := fc.RetrieveArtifacts(context.Background(), docChan); err != nil {
		t.Fatalf("RetrieveArtifacts() aborted on unreadable entry: %v", err)
	}
	close(docChan)

	var got []string
	for d := range docChan {
		got = append(got, string(d.Blob))
	}
	sort.Strings(got)

	want := []string{"a", "b"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("collected blobs = %v, want %v", got, want)
	}
}

func TestRetrieveArtifacts_UnreadableRootReturnsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions are not enforced the same way on windows")
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.json"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}
	// Restore so t.TempDir cleanup can remove everything.
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	// Permissions are not enforced for root or some filesystems; skip then.
	if _, err := os.ReadDir(root); err == nil {
		t.Skip("permissions cannot be enforced in this environment")
	}

	fc := NewFileCollector(context.Background(), root, false, 0)
	docChan := make(chan *processor.Document, 10)

	if err := fc.RetrieveArtifacts(context.Background(), docChan); err == nil {
		t.Fatal("RetrieveArtifacts() = nil, want error for unreadable root")
	}
}

func TestFileCollector_RecordsReadErrorMetric(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("relies on POSIX file permissions being enforced for a non-root user")
	}

	dir := t.TempDir()
	unreadable := filepath.Join(dir, "unreadable.json")
	if err := os.WriteFile(unreadable, []byte("test document content"), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatalf("failed to chmod test file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o644) })

	ctx := metrics.WithMetrics(context.Background(), "file_test")
	m := metrics.FromContext(ctx, "file_test")
	counter, err := m.RegisterCounter(ctx, FileReadErrorsCounter)
	if err != nil {
		t.Fatalf("failed to register counter: %v", err)
	}

	fc := NewFileCollector(ctx, dir, false, time.Second, WithMetrics(m))
	docChan := make(chan *processor.Document, 1)
	// Unreadable files below the root are skipped, not fatal, but still counted.
	if err := fc.RetrieveArtifacts(ctx, docChan); err != nil {
		t.Fatalf("RetrieveArtifacts() aborted on unreadable file: %v", err)
	}

	counterVec, ok := counter.(prometheus.Collector)
	if !ok {
		t.Fatal("counter should implement prometheus.Collector")
	}
	if err := testutil.CollectAndCompare(counterVec, strings.NewReader(`
		# HELP guac_file_test_file_read_errors Counter for file_test_file_read_errors
		# TYPE guac_file_test_file_read_errors counter
		guac_file_test_file_read_errors 1
	`)); err != nil {
		t.Errorf("unexpected metric state: %v", err)
	}
}
