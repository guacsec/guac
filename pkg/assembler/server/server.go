package server

import (
	"context"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

func GetGraphqlServer(ctx context.Context, backend backends.Backend) *handler.Server {
	topResolver := resolvers.Resolver{Backend: backend}
	config := generated.Config{Resolvers: &topResolver}
	config.Directives.Filter = resolvers.Filter
	srv := handler.NewDefaultServer(generated.NewExecutableSchema(config))
	return srv
}
