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
	"fmt"
	"io"
	"os"

	"github.com/fsnotify/fsnotify"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"gopkg.in/yaml.v3"
)

type fileDataSources struct {
	filePath string
}

type FileFormat struct {
	OciDataSources []string `yaml:"oci"`
	GitDataSources []string `yaml:"git"`
}

// NewFileDataSources creates a datasource which gets its data sources
// from a configuration file. This configuration file is in YAML and
// follows the structure outlined in the FileFormat struct. An example
// is as follows:
//
// sources.yaml
// ----
// oci:
// - oci://abc
// - oci://def
// git:
// - git+https://github.com/...
func NewFileDataSources(path string) (datasource.CollectSource, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	return &fileDataSources{
		filePath: path,
	}, nil
}

// GetDataSources returns a data source containing targets for the
// collector to collect
func (d *fileDataSources) GetDataSources(_ context.Context) (*datasource.DataSources, error) {
	f, err := os.Open(d.filePath)
	if err != nil {
		return nil, err
	}

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var df FileFormat
	if err := yaml.Unmarshal(b, &df); err != nil {
		return nil, err
	}
	return toDataSources(&df), nil
}

// DataSourcesUpdate will return a channel which will get an element
// if the CollectSource has new data. Upon update, nil is inserted
// into the channel and non-nil if the channel no longer is able to
// serve updates.
func (d *fileDataSources) DataSourcesUpdate(ctx context.Context) (<-chan error, error) {
	updateChan := make(chan error)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	err = watcher.Add(d.filePath)
	if err != nil {
		watcher.Close()
		return nil, err
	}

	go func() {
		defer watcher.Close()

		for {
			select {
			case ev, ok := <-watcher.Events:
				if !ok {
					updateChan <- fmt.Errorf("unexpected channel closure")
					return

				}
				if ev.Has(fsnotify.Write) {
					updateChan <- nil
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					updateChan <- fmt.Errorf("unexpected channel closure")
					return
				}
				updateChan <- err
				return

			case <-ctx.Done():
				err := fmt.Errorf("file watcher ending from context closure")
				updateChan <- err
				return
			}
		}
	}()
	return updateChan, nil
}

func toDataSources(f *FileFormat) *datasource.DataSources {
	var ociVals, gitVals []datasource.Source
	for _, s := range f.OciDataSources {
		ociVals = append(ociVals, datasource.Source{Value: s})
	}
	for _, s := range f.GitDataSources {
		gitVals = append(gitVals, datasource.Source{Value: s})
	}
	return &datasource.DataSources{
		OciDataSources: ociVals,
		GitDataSources: gitVals,
	}
}
