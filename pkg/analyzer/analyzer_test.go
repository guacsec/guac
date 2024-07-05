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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"testing"

	"github.com/dominikbraun/graph"
	analyzer "github.com/guacsec/guac/pkg/analyzer"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
)

var diffTestFile = "https://raw.githubusercontent.com/guacsec/guac-test/main/hasSbom-pairs/hasSBOM-syft-spdx-k8s.gcr.io-kube-apiserver.v1.24.1.json"

func readTestFileFromHub(fileUrl string) ([]byte, error){

	resp, err := http.Get(fileUrl)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    return body, nil
}

func TestSetGetNodeAttribute(t *testing.T) {
	g := graph.New(analyzer.NodeHash, graph.Directed())
	analyzer.AddGraphNode(g, "id", "black")
	if !analyzer.SetNodeAttribute(g, "id", "key", "value") {
		t.Errorf("(set)Expected no error, got error")
	}
	value, err := analyzer.GetNodeAttribute(g, "id", "key")
	if err != nil {
		t.Errorf("(get)Expected no error, got error %v", err)
	}
	value, ok := value.(string)
	if !ok {
		t.Errorf("Expected no error, got ")
	}

	if value != "value" {
		t.Errorf("Expected value %s, got %s", "value", value)
	}
}

func TestHighlightAnalysis(t *testing.T) {

	data, err  := readTestFileFromHub(diffTestFile)
	if err != nil {
		t.Errorf("Error reading test JSON")
	}

	var sboms []model.HasSBOMsHasSBOM

	err = json.Unmarshal(data, &sboms)
	if err != nil {
		t.Errorf("Error unmarshaling JSON")
	}

	graphOne, errOne := analyzer.MakeGraph(sboms[0], false, false, false, false, false)

	graphTwo, errTwo := analyzer.MakeGraph(sboms[1], false, false, false, false, false)

	if errOne != nil || errTwo != nil {
		t.Errorf("Error making graph %v %v", errOne.Error(), errTwo.Error())
	}

	one, two,err := analyzer.HighlightAnalysis(graphOne, graphTwo, 0)

	if err != nil {
		t.Errorf("Error highlighting diff %v", err.Error())
	}
	if len(one) == 0 || len(two) == 0 {
		t.Errorf("Error highlighting diff, wanted diffs got 0")
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

	_, err := g.Edge("from", "to")
	if err != nil {
		t.Errorf("Error getting edge from %s to %s: %v", "from", "to", err)
	}
}

func TestEquivalence(t *testing.T){
	data, err  := readTestFileFromHub(diffTestFile)
	if err != nil {
		t.Errorf("Error reading test file %v", err.Error())
	}

	var sboms []model.HasSBOMsHasSBOM

	err = json.Unmarshal(data, &sboms)
	if err != nil {
		t.Errorf("Error unmarshaling JSON")
	}

	for _, val := range sboms {
		graphOne, errOne := analyzer.MakeGraph(val, false, false, false, false, false)

		graphTwo, errTwo := analyzer.MakeGraph(val, false, false, false, false, false)

		if errOne != nil || errTwo != nil {
			t.Errorf("Error making graph %v %v", errOne.Error(), errTwo.Error())
		}

		ok, err := analyzer.GraphEqual(graphOne, graphTwo)
		if !ok {
			t.Errorf("Reconstructed graph not equal " + err.Error())
		}


		ok, err = analyzer.GraphEdgesEqual(graphOne, graphTwo)
		if !ok {
			t.Errorf("Reconstructed graph edges not equal  " + err.Error())
		}
	}

	
}
