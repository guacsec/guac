//
// Copyright 2024 The GUAC Authors.
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

package analyzer_test

import (

	"testing"

	"github.com/dominikbraun/graph"
	analyzer "github.com/guacsec/guac/pkg/analyzer"

)

func TestSetGetNodeAttribute(t *testing.T) {
	g := graph.New(analyzer.NodeHash, graph.Directed())
	analyzer.AddGraphNode(g, "id", "black")
	analyzer.SetNodeAttribute(g,"id", "key", "value")
	value, err := analyzer.GetNodeAttribute(g, "id", "key")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	value, ok := value.(string)
	if !ok {
		t.Errorf("Expected no error, got ",)
	}

	if value != "value" {
		t.Errorf("Expected value %s, got %s", "value", value)
	}

}

func TestHighlightAnalysis(t *testing.T) {
	//not exhaustive, can be made better

	g := graph.New(analyzer.NodeHash, graph.Directed())

	//create HasSBOM node
	analyzer.AddGraphNode(g, "HasSBOM", "black")
  
	analyzer.SetNodeAttribute(g, "HasSBOM", "Algorithm" , "hasSBOM.Algorithm")
	analyzer.SetNodeAttribute(g, "HasSBOM", "Collector" , "hasSBOM.Collector")
	analyzer.SetNodeAttribute(g, "HasSBOM", "Digest" , "hasSBOM.Digest")
	analyzer.SetNodeAttribute(g, "HasSBOM", "DownloadLocation" , "hasSBOM.DownloadLocation")
	analyzer.SetNodeAttribute(g, "HasSBOM", "KnownSince" , "hasSBOM.KnownSince")
	analyzer.SetNodeAttribute(g, "HasSBOM", "Origin" , "hasSBOM.Origin")

	_, diff, err := analyzer.HighlightAnalysis(g,g ,0)
	if err !=  nil {
		t.Errorf("Error running highlight analysis: %v", err)
	}
	if len(diff.MetadataMismatch) != 0 && len(diff.MissingAddedRemovedLinks) != 0 && len(diff.MissingAddedRemovedNodes) != 0 {
		t.Errorf("Expected no diffs, got diffs %+v", diff)
	}
}

func TestAddGraphNode(t *testing.T) {
	g := graph.New(analyzer.NodeHash, graph.Directed())
	analyzer.AddGraphNode(g, "id", "black")
	_, err := g.Vertex("id")
	if err != nil {
		t.Errorf("Error adding node with id 'id': %v", err)
	}
}

func TestAddGraphEdge(t *testing.T) {
	g := graph.New(analyzer.NodeHash, graph.Directed())
	analyzer.AddGraphEdge(g, "from", "to", "black")

	_, err  := g.Edge("from", "to")
	if err != nil {
		t.Errorf("Error getting edge from %s to %s: %v", "from", "to", err)
	}
}
