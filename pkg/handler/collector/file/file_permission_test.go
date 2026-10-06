//
// Copyright 2026 The GUAC Authors.
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
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/guacsec/guac/pkg/handler/processor"
)

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
