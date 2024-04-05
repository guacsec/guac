package guacanalyze_test

import (

	"testing"


	"github.com/dominikbraun/graph"
	analyze "github.com/guacsec/guac/pkg/analyzer"

)

func TestSetGetNodeAttribute(t *testing.T) {
	g := graph.New(analyze.NodeHash, graph.Directed())
	analyze.AddGraphNode(g, "id", "black")
	analyze.SetNodeAttribute(g,"id", "key", "value")
	value, ok := analyze.GetNodeAttribute(g, "id", "key").(string)
	if !ok {
		t.Errorf("Expected no error, got ",)
	}

	if value != "value" {
		t.Errorf("Expected value %s, got %s", "value", value)
	}

}

func TestHighlightAnalysis(t *testing.T) {
	//not exhaustive, can be made better

	g := graph.New(analyze.NodeHash, graph.Directed())

	//create HasSBOM node
	analyze.AddGraphNode(g, "HasSBOM", "black")
  
	analyze.SetNodeAttribute(g, "HasSBOM", "Algorithm" , "hasSBOM.Algorithm")
	analyze.SetNodeAttribute(g, "HasSBOM", "Collector" , "hasSBOM.Collector")
	analyze.SetNodeAttribute(g, "HasSBOM", "Digest" , "hasSBOM.Digest")
	analyze.SetNodeAttribute(g, "HasSBOM", "DownloadLocation" , "hasSBOM.DownloadLocation")
	analyze.SetNodeAttribute(g, "HasSBOM", "KnownSince" , "hasSBOM.KnownSince")
	analyze.SetNodeAttribute(g, "HasSBOM", "Origin" , "hasSBOM.Origin")

	_, diff := analyze.HighlightAnalysis(g,g ,0)
	if len(diff.MetadataMismatch) != 0 && len(diff.MissingAddedRemovedLinks) != 0 && len(diff.MissingAddedRemovedNodes) != 0 {
		t.Errorf("Expected no diffs, got diffs %+v", diff)
	}
}

func TestAddGraphNode(t *testing.T) {
	g := graph.New(analyze.NodeHash, graph.Directed())
	analyze.AddGraphNode(g, "id", "black")
	_, err := g.Vertex("id")
	if err != nil {
		t.Errorf("Error adding node with id 'id': %v", err)
	}
}

func TestAddGraphEdge(t *testing.T) {
	g := graph.New(analyze.NodeHash, graph.Directed())
	analyze.AddGraphEdge(g, "from", "to", "black")

	_, err  := g.Edge("from", "to")
	if err != nil {
		t.Errorf("Error getting edge from %s to %s: %v", "from", "to", err)
	}
}
