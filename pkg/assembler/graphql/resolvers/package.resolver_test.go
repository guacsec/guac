package resolvers_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/guacsec/guac/internal/testing/mocks"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

func TestPackages(t *testing.T) {
	tests := []struct {
		Name        string
		Query       *model.PkgSpec
		ExpQueryErr bool
	}{
		{
			Name:        "Happy path",
			Query:       &model.PkgSpec{},
			ExpQueryErr: false,
		},
	}
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}
			times := 1
			if test.ExpQueryErr {
				times = 0
			}
			b.
				EXPECT().
				Packages(ctx, test.Query).
				Times(times)
			_, err := r.Query().Packages(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
		})
	}
}
