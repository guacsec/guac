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

package assembler

import (
	"reflect"
	"strings"

	"github.com/guacsec/guac/pkg/handler/processor"
)

// objectMetadata appends metadata associated with the node
type objectMetadata struct {
	// sourceInfo is the file location from which the node was created
	sourceInfo string
	// collectorInfo is the collector from which the file that created the node came from
	collectorInfo string
}

// NewObjectMetadata creates a new instance to add metadata to nodes
func NewObjectMetadata(s processor.SourceInformation) *objectMetadata {
	return &objectMetadata{
		sourceInfo:    s.Source,
		collectorInfo: s.Collector,
	}
}

func (o *objectMetadata) addProperties(prop map[string]interface{}) {
	if len(o.sourceInfo) > 0 {
		prop["source"] = o.sourceInfo
	}
	if len(o.collectorInfo) > 0 {
		prop["collector"] = o.collectorInfo
	}
}

func (o *objectMetadata) getProperties() []string {
	return []string{"source", "collector"}
}

func isDefined(v interface{}) bool {
	return !reflect.ValueOf(v).IsZero()
}

func toLower(v ...string) []string {
	lowerVals := []string{}
	for _, val := range v {
		lowerVals = append(lowerVals, strings.ToLower(val))
	}
	return lowerVals
}
