package server

import (
	"context"
	"testing"

	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"

	"github.com/guacsec/guac/internal/testing/stablememmap"
	"github.com/guacsec/guac/pkg/assembler/backends"
)

func TestGetGraphqlServer(t *testing.T) {
	ctx := context.Background()

	store := stablememmap.GetStore()
	backend, err := backends.Get("keyvalue", ctx, store)
	if err != nil {
		t.Errorf("Error getting backend: %v", err)
	}

	srv := GetGraphqlServer(ctx, backend)
	if srv == nil {
		t.Errorf("Expected GetGraphqlServer to return a non-nil server")
	}
}
