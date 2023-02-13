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

package csubsource

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/collectsub"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
)

func createSimpleCsubClient(ctx context.Context) (client.Client, error) {
	c, err := client.NewMockClient()
	if err != nil {
		return nil, fmt.Errorf("unable to create mock client: %w", err)
	}

	err = c.AddCollectEntries(ctx, []*collectsub.CollectEntry{
		{Type: collectsub.CollectDataType_DATATYPE_OCI, Value: "abc"},
		{Type: collectsub.CollectDataType_DATATYPE_OCI, Value: "def"},
		{Type: collectsub.CollectDataType_DATATYPE_GIT, Value: "git+https://github.com/guacsec/guac"},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to add collect entries: %w", err)
	}
	return c, nil
}

func Test_FileSourceGetDataSources(t *testing.T) {
	ctx := context.TODO()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	c, err := createSimpleCsubClient(ctx)
	if err != nil {
		t.Errorf("unable to initiliaze simple source client: %v", err)
		return
	}
	defer c.Close()

	cds, err := NewCsubDatasource(c, time.Second)
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

	c, err := createSimpleCsubClient(ctx)
	if err != nil {
		t.Errorf("unable to initiliaze simple source client: %v", err)
		return
	}
	defer c.Close()

	cds, err := NewCsubDatasource(c, time.Second)
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
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	go func() {
		err := c.AddCollectEntries(ctx, []*collectsub.CollectEntry{
			{Type: collectsub.CollectDataType_DATATYPE_GIT, Value: "git+newentry"},
		})
		if err != nil {
			t.Errorf("got error from trying to add new entries: %v", err)
		}
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
