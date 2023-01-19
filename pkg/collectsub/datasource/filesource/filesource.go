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
// follows the sturcture outlined in the FileFormat struct. An example
// is as follows:
//
// sources.yaml
// ----
// oci:
// - oci://abc
// - oci://def
// git:
// - git+https://github.com/...
func NewFileDataSources(path string) datasource.CollectSource {
	return &fileDataSources{
		filePath: path,
	}
}

// GetDataSources returns a data source containing targets for the
// collector to collect
func (d *fileDataSources) GetDataSources() (*datasource.DataSources, error) {
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
func (d *fileDataSources) DataSourcesUpdate() (<-chan error, error) {
	updateChan := make(chan error)
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			updateChan <- err
		}
		defer watcher.Close()
		watcher.Add(d.filePath)

		for {
			select {
			case ev, ok := <-watcher.Events:
				if !ok {
					updateChan <- fmt.Errorf("unexpected channel closure")
					return

				}
				fmt.Printf("GOT EVENT: %+v\n", ev)
				if ev.Has(fsnotify.Write) {
					updateChan <- nil
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					updateChan <- fmt.Errorf("unexpected channel closure")
					return
				}
				updateChan <- err
				fmt.Printf("got err while watching: %+v\n", err)
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
