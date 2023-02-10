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

package inmemsource

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
)

func Test_InmemSourceGetDataSources(t *testing.T) {
	ctx := context.TODO()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	expected := &datasource.DataSources{
		OciDataSources: []datasource.Source{
			{Value: "abc"},
			{Value: "def"},
		},
		GitDataSources: []datasource.Source{
			{Value: "git+https://github.com/guacsec/guac"},
		},
	}

	cds, err := NewInmemDataSources(expected)
	if err != nil {
		t.Errorf("unable to initiliaze InmemDataSources: %v", err)
	}
	ds, err := cds.GetDataSources(ctx)
	if err != nil {
		t.Errorf("unable to get DataSources: %v", err)
		return
	}

	if !reflect.DeepEqual(ds, expected) {
		t.Errorf("unexpected datasource output: expect %v, got %v", expected, ds)
	}
}

func Test_InmemSourceDataSourcesUpdate(t *testing.T) {
	ctx := context.TODO()

	expected := &datasource.DataSources{
		OciDataSources: []datasource.Source{
			{Value: "abc"},
			{Value: "def"},
		},
		GitDataSources: []datasource.Source{
			{Value: "git+https://github.com/guacsec/guac"},
		},
	}

	cds, err := NewInmemDataSources(expected)
	if err != nil {
		t.Errorf("unable to initiliaze InmemDataSources: %v", err)
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

	if !reflect.DeepEqual(ds, expected) {
		t.Errorf("unexpected datasource output: expect %v, got %v", expected, ds)

	}

	// Check for update
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	expectedNew := &datasource.DataSources{
		OciDataSources: []datasource.Source{
			{Value: "abc"},
			{Value: "def"},
		},
		GitDataSources: []datasource.Source{
			{Value: "git+https://github.com/guacsec/guac"},
			{Value: "git+newentry"},
		},
	}

	go func() {
		cds.UpdateDataSources(expectedNew)
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

	if !reflect.DeepEqual(ds, expectedNew) {
		t.Errorf("unexpected datasource output: expect %v, got %v", expected, ds)
	}
}
