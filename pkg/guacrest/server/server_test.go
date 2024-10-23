package server

import (
	"context"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"testing"

	. "github.com/guacsec/guac/internal/testing/graphqlClients"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_ClientErrors(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name   string
		data   GuacData
		purl   string
		digest string
	}{{
		name: "Package not found",
		purl: "pkg:guac/foo",
	}, {
		name: "Package not found because version was specified",
		data: GuacData{Packages: []string{"pkg:guac/foo"}},
		purl: "pkg:guac/foo@v1",
	}, {
		name: "Package not found because version was not specified",
		data: GuacData{Packages: []string{"pkg:guac/foo@v1"}},
		purl: "pkg:guac/foo",
	}, {
		name: "Package not found due to missing qualifiers",
		data: GuacData{Packages: []string{"pkg:guac/foo?a=b"}},
		purl: "pkg:guac/foo",
	}, {
		name: "Package not found due to providing qualifiers",
		data: GuacData{Packages: []string{"pkg:guac/foo"}},
		purl: "pkg:guac/foo?a=b",
	}, {
		name:   "Artifact not found because version was not specified",
		digest: "sha-abc",
	}, {
		name: "Neither Purl nor Digest provided",
	}, {
		name:   "Unrecognized link condition",
		digest: "sha-abc",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gqlClient := SetupTest(t)
			Ingest(ctx, t, gqlClient, tt.data)

			restApi := NewDefaultServer(gqlClient)

			if tt.purl != "" {
				res, err := restApi.GetPackageDeps(ctx, gen.GetPackageDepsRequestObject{
					Purl: tt.purl,
				})
				if err != nil {
					t.Fatalf("GetPackageDeps returned unexpected error: %v", err)
				}
				if !isBadRequestResponse(res) {
					t.Fatalf("Did not receive a 400 Response: received %v of type %T", res, res)
				}
			}

			if tt.digest != "" {
				res, err := restApi.GetArtifactDeps(ctx, gen.GetArtifactDepsRequestObject{
					Digest: tt.digest,
				})
				if err != nil {
					t.Fatalf("GetArtifactDeps returned unexpected error: %v", err)
				}
				if !isBadRequestResponse(res) {
					t.Fatalf("Did not receive a 400 Response: received %v of type %T", res, res)
				}
			}
		})
	}
}

func Test_DefaultLinkCondition(t *testing.T) {
	/******** set up the test ********/
	ctx := logging.WithLogger(context.Background())
	gqlClient := SetupTest(t)
	restApi := NewDefaultServer(gqlClient)
	data := GuacData{
		Packages: []string{"pkg:guac/foo", "pkg:guac/bar"},
		HasSboms: []HasSbom{{
			Subject:          "pkg:guac/foo",
			IncludedSoftware: []string{"pkg:guac/bar"}},
		}}
	Ingest(ctx, t, gqlClient, data)

	/******** call the endpoint ********/
	res, err := restApi.GetPackageDeps(ctx, gen.GetPackageDepsRequestObject{
		Purl: "pkg:guac/foo",
	})
	if err != nil {
		t.Fatalf("RetrieveDependencies returned unexpected error: %v", err)
	}

	/******** check the output ********/
	switch res.(type) {
	case gen.GetPackageDeps200JSONResponse:
	case gen.GetPackageDeps400JSONResponse, gen.GetPackageDeps500JSONResponse, gen.GetPackageDeps502JSONResponse:
		t.Fatalf("Did not receive a 200 Response: received %v", res)
	default:
		t.Fatalf("Unexpected response type: %T", res)
	}
}

// Helper function to check if the response is a 400 error
func isBadRequestResponse(res interface{}) bool {
	switch res.(type) {
	case gen.GetPackagePurls400JSONResponse,
		gen.GetPackageDeps400JSONResponse,
		gen.GetPackageVulns400JSONResponse,
		gen.GetArtifactDeps400JSONResponse,
		gen.GetArtifactVulns400JSONResponse:
		return true
	default:
		return false
	}
}
