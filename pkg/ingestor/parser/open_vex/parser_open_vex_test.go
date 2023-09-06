package open_vex

import (
	"context"
	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/openvex/go-vex/pkg/vex"
	"testing"
)

var testData = `{
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/docs/public/vex-a06f9de1ad1b1e555a33b2d0c1e7e6ecc4dc1800ff457c61ea09d8e97670d2a3",
  "author": "Wolfi J. Inkinson",
  "role": "Senior VEXing Engineer",
  "timestamp": "2023-01-09T21:23:03.579712389-06:00",
  "version": "1",
  "statements": [
    {
      "vulnerability": "CVE-2023-12345",
      "products": [
        "pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb"
      ],
      "subcomponents": [
        "pkg:apk/alpine/git@2.38.1-r0?arch=x86_64",
        "pkg:apk/alpine/git@2.38.1-r0?arch=ppc64le"
      ],
      "status": "not_affected",
      "justification": "inline_mitigations_already_exist",
      "impact_statement": "Included git is mitigated against CVE-2023-12345 !"
    }
  ]
}`

func Test_openVEXParser_Parse(t *testing.T) {
	type args struct {
		ctx context.Context
		doc *processor.Document
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test",
			args: args{
				ctx: context.Background(),
				doc: &processor.Document{Blob: []byte(testData)},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newParser := NewOpenVEXParser()
			if err := newParser.Parse(tt.args.ctx, tt.args.doc); (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_openVEXParser_GetPredicates(t *testing.T) {
	newVEX := vex.New()

	newVEX.Statements = append(newVEX.Statements, vex.Statement{
		Vulnerability: "CVE-2023-12345",
		Products: []string{
			"pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb",
		},
		Subcomponents: []string{
			"pkg:apk/alpine/git@2.38.1-r0?arch=x86_64",
			"pkg:apk/alpine/git@2.38.1-r0?arch=ppc64le",
		},
		Status:          "not_affected",
		Justification:   "inline_mitigations_already_exist",
		ImpactStatement: "Included git is mitigated against CVE-2023-12345 !",
	})

	type fields struct {
		doc               *processor.Document
		identifierStrings *common.IdentifierStrings
		openVex           *vex.VEX
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *assembler.IngestPredicates
	}{
		{
			name: "default",
			fields: fields{
				openVex: &newVEX,
			},
			args: args{
				ctx: context.Background(),
			},
			want: &assembler.IngestPredicates{
				Vex: []assembler.VexIngest{
					{
						Pkg: &generated.PkgInputSpec{
							Name:      "git",
							Version:   strP("sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb"),
							Namespace: strP(""),
							Type:      "oci",
							Subpath:   strP(""),
						},
						Artifact: nil,
						Vulnerability: &generated.VulnerabilityInputSpec{
							Type:            "cve",
							VulnerabilityID: "cve-2023-12345",
						},
						VexData: &generated.VexStatementInputSpec{
							KnownSince:       *newVEX.Metadata.Timestamp,
							Origin:           newVEX.Metadata.ID,
							VexJustification: generated.VexJustificationInlineMitigationsAlreadyExist,
							Status:           generated.VexStatusNotAffected,
							Statement:        newVEX.Statements[0].ImpactStatement,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &openVEXParser{
				doc:               tt.fields.doc,
				identifierStrings: tt.fields.identifierStrings,
				openVex:           tt.fields.openVex,
			}
			got := c.GetPredicates(tt.args.ctx)

			if d := cmp.Diff(tt.want, got, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
				t.Errorf("csaf.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}

func strP(s string) *string {
	return &s
}
