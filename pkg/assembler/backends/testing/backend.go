package backend

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type DemoCredentials struct {}

type demoClient struct {}

func GetBackend(args backends.BackendArgs) (backends.Backend, error) {
	return &demoClient{}, nil
}

func (c *demoClient) Artifacts(ctx context.Context) ([]*model.Artifact, error) {
	panic(fmt.Errorf("not implemented: Artifacts - artifacts in testing backend"))
}
