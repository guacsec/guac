//
// Copyright 2023 The GUAC Authors.
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

package filesource

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
)

var simpleConfig = []byte(`oci:
- abc
- def
git:
- git+https://github.com/guacsec/guac`)

func Test_FileSourceGetDataSources(t *testing.T) {
	ctx := context.TODO()
	tmpDir, err := os.MkdirTemp("", "test-file-source")
	if err != nil {
		t.Fatal("unable to create temp dir")
	}
	defer os.RemoveAll(tmpDir)

	path, err := createTestFile(tmpDir, "test1.yaml", simpleConfig)
	if err != nil {
		t.Fatal("unable to create test file")
	}

	cds, err := NewFileDataSources(path)
	if err != nil {
		t.Errorf("unable to create FileDataSources: %v", err)
		return
	}

	ds, err := cds.GetDataSources(ctx)
	if err != nil {
		t.Errorf("unable to get DataSources: %v", err)
		return
	}

	expected := &datasource.DataSources{
		OciDataSources: []datasource.Source{
			{Value: "abc"},
			{Value: "def"},
		},
		GitDataSources: []datasource.Source{
			{Value: "git+https://github.com/guacsec/guac"},
		},
	}

	if !reflect.DeepEqual(ds, expected) {
		t.Errorf("unexpected datasource output: expect %v, got %v", expected, ds)
	}
}

func Test_FileSourceDataSourcesUpdate(t *testing.T) {
	ctx := context.TODO()
	tmpDir, err := os.MkdirTemp("", "test-file-source")
	if err != nil {
		t.Fatal("unable to create temp dir")
	}
	defer os.RemoveAll(tmpDir)

	path, err := createTestFile(tmpDir, "test1.yaml", simpleConfig)
	if err != nil {
		t.Fatal("unable to create test file")
	}

	cds, err := NewFileDataSources(path)
	if err != nil {
		t.Errorf("unable to create FileDataSources: %v", err)
		return
	}
	upChan, err := cds.DataSourcesUpdate(ctx)
	if err != nil {
		t.Errorf("unable to get DataSourcesUpdate: %v", err)
	}

	ds, err := cds.GetDataSources(ctx)
	if err != nil {
		t.Errorf("unable to get DataSources: %v", err)
		return
	}

	expected := &datasource.DataSources{
		OciDataSources: []datasource.Source{
			{Value: "abc"},
			{Value: "def"},
		},
		GitDataSources: []datasource.Source{
			{Value: "git+https://github.com/guacsec/guac"},
		},
	}

	if !reflect.DeepEqual(ds, expected) {
		t.Errorf("unexpected datasource output: expect %v, got %v", expected, ds)

	}

	// Check for update
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	go func() {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Errorf("unable to open file to append: %v", err)
			return
		}
		_, err = f.Write([]byte("\n- git+newentry"))
		if err != nil {
			t.Errorf("unable to append to file: %v", err)
		}
		f.Close()
	}()
	select {
	case err = <-upChan:
		if err != nil {
			t.Errorf("got error from update channel: %v", err)
			return
		}
	case <-ctx.Done():
		t.Errorf("test timed out")
		return
	}

	// Get new data source and compare
	ds, err = cds.GetDataSources(ctx)
	if err != nil {
		t.Errorf("unable to get DataSources: %v", err)
		return
	}

	expected = &datasource.DataSources{
		OciDataSources: []datasource.Source{
			{Value: "abc"},
			{Value: "def"},
		},
		GitDataSources: []datasource.Source{
			{Value: "git+https://github.com/guacsec/guac"},
			{Value: "git+newentry"},
		},
	}

	if !reflect.DeepEqual(ds, expected) {
		t.Errorf("unexpected datasource output: expect %v, got %v", expected, ds)
	}

}

func createTestFile(dir string, name string, content []byte) (string, error) {
	path := filepath.Join(dir, name)
	return path, os.WriteFile(path, content, 0644)
}
