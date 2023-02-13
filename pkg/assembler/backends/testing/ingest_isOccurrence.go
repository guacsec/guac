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

package testing

import (
	"fmt"
	"reflect"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllIsOccurrence(client *demoClient) error {

	err := client.registerIsOccurrence(client.packages[2], nil, []*model.Artifact{{Digest: "5a787865sd676dacb0142afa0b83029cd7befd9", Algorithm: "sha1"},
		{Digest: "89bb0da1891646e58eb3e6ed24f3a6fc3c8eb5a0d44824cba581dfa34a0450cf", Algorithm: "sha256"}}, "this artifact is an occurrence of this package")
	if err != nil {
		return err
	}
	err = client.registerIsOccurrence(nil, client.sources[0], []*model.Artifact{client.artifacts[0]}, "this artifact is an occurrence of this source")
	if err != nil {
		return err
	}
	return nil
}
func (c *demoClient) registerIsOccurrence(selectedPackage *model.Package, selectedSource *model.Source, artifacts []*model.Artifact, justification string) error {

	if selectedPackage != nil && selectedSource != nil {
		return fmt.Errorf("cannot specify both package and source for IsOccurrence")
	}

	for _, occurrence := range c.isOccurrence {
		if reflect.DeepEqual(occurrence.OccurrenceArtifacts, artifacts) && occurrence.Justification == justification &&
			occurrence.Package == selectedPackage || occurrence.Source == selectedSource {
			return nil
		}
	}

	newIsOccurrence := &model.IsOccurrence{
		Justification:       justification,
		Package:             selectedPackage,
		Source:              selectedSource,
		OccurrenceArtifacts: artifacts,
		Origin:              "testing backend",
		Collector:           "testing backend",
	}
	c.isOccurrence = append(c.isOccurrence, newIsOccurrence)
	return nil
}
