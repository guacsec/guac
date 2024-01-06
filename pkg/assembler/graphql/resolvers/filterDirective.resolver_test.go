package resolvers_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	"github.com/guacsec/guac/internal/testing/mocks"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func ConvertToGQLResolver(mockResolver *mocks.MockResolver) graphql.Resolver {
	return mockResolver.Resolver
}

func TestFilter(t *testing.T) {
	ctx := context.Background()

	createMockResolver := func(resolveFunc func(context.Context) (interface{}, error)) *mocks.MockResolver {
		return &mocks.MockResolver{
			ResolveFunc: resolveFunc,
		}
	}

	createGQLResolver := func(mockResolver *mocks.MockResolver) graphql.Resolver {
		return ConvertToGQLResolver(mockResolver)
	}

	tests := []struct {
		Name             string
		KeyName          string
		Operation        model.FilterOperation
		Value            string
		Resolver         *mocks.MockResolver
		ExpectedResult   interface{}
		ExpectedError    bool
		ExpectedErrorMsg string
	}{
		{
			Name:      "FilterMetadata by origin startswith 'guac'",
			KeyName:   "Origin",
			Operation: model.FilterOperationStartswith,
			Value:     "guac",
			Resolver: createMockResolver(func(ctx context.Context) (interface{}, error) {
				return testdata.Metadata, nil
			}),
			ExpectedResult: testdata.Metadata,
			ExpectedError:  false,
		},
		{
			Name:      "Filter Metadata by Id Contains '9903'",
			KeyName:   "Id",
			Operation: model.FilterOperationContains,
			Value:     "9903",
			Resolver: createMockResolver(func(ctx context.Context) (interface{}, error) {
				return []*model.HasMetadata{testdata.Metadata[1]}, nil
			}),
			ExpectedResult: []*model.HasMetadata{testdata.Metadata[1]},
			ExpectedError:  false,
		},
		{
			Name:      "Filter Artifacts by Digest Contains 'fadf546'",
			KeyName:   "Digest",
			Operation: model.FilterOperationContains,
			Value:     "fadf546",
			Resolver: createMockResolver(func(ctx context.Context) (interface{}, error) {
				return []*model.Artifact{testdata.ArtifactData[1]}, nil
			}),
			ExpectedResult: []*model.Artifact{testdata.ArtifactData[1]},
			ExpectedError:  false,
		},
		{
			Name:      "Filter Artifacts by Algorithm StartsWith 'sha'",
			KeyName:   "subject.Algorithm",
			Operation: model.FilterOperationStartswith,
			Value:     "sha2",
			Resolver: createMockResolver(func(ctx context.Context) (interface{}, error) {
				return testdata.H1, nil
			}),
			ExpectedResult: testdata.H1out,
			ExpectedError:  false,
		},
		{
			Name:      "Filter Artifacts by Algorithm StartsWith 'sha'",
			KeyName:   "Namespaces[].Names[].name",
			Operation: model.FilterOperationStartswith,
			Value:     "github",
			Resolver: createMockResolver(func(ctx context.Context) (interface{}, error) {
				return testdata.P6, nil
			}),
			ExpectedResult: testdata.P6out,
			ExpectedError:  false,
		},
		
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			result, err := resolvers.Filter(ctx, nil, createGQLResolver(test.Resolver), &test.KeyName, &test.Operation, &test.Value)

			if (err != nil) != test.ExpectedError {
				t.Fatalf("Unexpected error: %v", err)
			}

			if test.ExpectedError && err != nil {
				expectedError := gqlerror.Error{
					Message: test.ExpectedErrorMsg,
				}
				if err.Error() != expectedError.Error() {
					t.Fatalf("Expected error message '%s', but got '%s'", expectedError.Error(), err.Error())
				}
				return
			}
			if !reflect.DeepEqual(result, test.ExpectedResult) {
				t.Fatalf("Expected result %v, but got %v", test.ExpectedResult, result)
			}
		})
	}
}
