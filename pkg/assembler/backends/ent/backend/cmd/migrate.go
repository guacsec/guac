package main

import (
	"context"

	"entgo.io/ent/dialect"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/backend"
)

func main() {
	ctx := context.Background()

	_, err := backend.SetupBackend(ctx, backend.BackendOptions{
		AutoMigrate: true,
		DriverName:  dialect.Postgres,
		Address:     "postgres://localhost:5432/guac?sslmode=disable",
	})

	if err != nil {
		panic(err)
	}
}
