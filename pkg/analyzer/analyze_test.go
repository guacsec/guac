package guacanalyze_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/Khan/genqlient/graphql"
	"github.com/dominikbraun/graph"
	analyze "github.com/guacsec/guac/pkg/analyzer"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
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
	//both to be same sizes for testing
	//not exhaustive, can be made better
	ctx := logging.WithLogger(context.Background())
    httpClient := http.Client{}
    gqlclient := graphql.NewClient("http://localhost:8080/query", &httpClient)
	var bomOne, bomTwo *model.HasSBOMsHasSBOM
	bom, err := analyze.FindHasSBOMBy( model.HasSBOMSpec{} ,"", "", "", ctx, gqlclient)
    if err != nil {
		t.Errorf("Error finding first SBOM: %v", err)
    }
	bomOne = &bom.HasSBOM[0]
	bomTwo = &bom.HasSBOM[0]

	gOne := analyze.MakeGraph(*bomOne, false, false, false, false, false)
	gTwo := analyze.MakeGraph(*bomTwo, false, false, false, false, false)

	_, diff := analyze.HighlightAnalysis(gOne, gTwo ,0)
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
