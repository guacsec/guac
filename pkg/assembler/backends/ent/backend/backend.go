package backend

import (
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"golang.org/x/exp/slices"

	// Import regular postgres driver
	_ "github.com/lib/pq"
)

var (
	PathContains = slices.Contains[string]
	Errorf       = gqlerror.Errorf
)

// MaxPageSize is the maximum number of results that will be returned in a single query.
const MaxPageSize = 1000

type EntBackend struct {
	backends.Backend
	client *ent.Client
}

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	be := &EntBackend{}
	if args == nil {
		return nil, fmt.Errorf("invalid args: WithClient is required, got nil")
	}

	if client, ok := args.(*ent.Client); ok {
		be.client = client
	} else {
		return nil, fmt.Errorf("invalid args type")
	}

	return be, nil
}
