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

package datasource

import (
	"fmt"
	"io"
	"os"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

type fileDataSource struct {
	filePath string
}

type FileFormat struct {
	OciDataSource  []string `yaml:"oci"`
	GitDataSource  []string `yaml:"git"`
	PurlDataSource []string `yaml:"purl"`
}

/*

sources.yaml
----
oci:
- oci://abc
- oci://def
purl:
- pkg://deb....

*/

func NewFileDataSource(path string) (CollectSource, error) {
	return &fileDataSource{
		filePath: path,
	}, nil
}

// GetDataSource returns a data source containing targets for the
// collector to collect
func (d *fileDataSource) GetDataSource() (*DataSource, error) {
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
	return toDataSource(&df), nil
}

// DataSourceUpdate will return a channel which will get an element
// if the CollectSource has new data. Upon update, nil is inserted
// into the channel and non-nil if the channel no longer is able to
// serve updates.
func (d *fileDataSource) DataSourceUpdate() <-chan error {
	updateChan := make(chan error)
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			updateChan <- err
		}
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
			}
		}
	}()
	return updateChan
}

func toDataSource(f *FileFormat) *DataSource {
	var ociVals, gitVals, purlVals []Source
	for _, s := range f.OciDataSource {
		ociVals = append(ociVals, Source{Value: s})
	}
	for _, s := range f.GitDataSource {
		gitVals = append(gitVals, Source{Value: s})
	}
	for _, s := range f.PurlDataSource {
		purlVals = append(purlVals, Source{Value: s})
	}
	return &DataSource{
		OciDataSource:  ociVals,
		GitDataSource:  gitVals,
		PurlDataSource: purlVals,
	}
}
