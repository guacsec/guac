package backend

import (
	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) TestSources() {
	ctx := s.Ctx
	tests := []struct {
		name       string
		srcInput   *model.SourceInputSpec
		srcFilter  *model.SourceSpec
		idInFilter bool
		want       []*model.Source
		wantErr    bool
	}{{
		name:     "myrepo with tag",
		srcInput: s1,
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: false,
		want:       []*model.Source{s1out},
		wantErr:    false,
	}, {
		name:     "myrepo with tag, ID search",
		srcInput: s1,
		srcFilter: &model.SourceSpec{
			Name: ptrfrom.String("myrepo"),
		},
		idInFilter: true,
		want:       []*model.Source{s1out},
		wantErr:    false,
	}, {
		name:     "bobsrepo with commit",
		srcInput: s2,
		srcFilter: &model.SourceSpec{
			Namespace: ptrfrom.String("github.com/bob"),
			Commit:    ptrfrom.String("5e7c41f"),
		},
		want: []*model.Source{s2out},
	}, {
		name:     "bobsrepo with commit, type search",
		srcInput: s2,
		srcFilter: &model.SourceSpec{
			Type:      ptrfrom.String("git"),
			Namespace: ptrfrom.String("github.com/bob"),
			Commit:    ptrfrom.String("5e7c41f"),
		},
		idInFilter: false,
		want:       []*model.Source{s2out},
		wantErr:    false,
	}}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			t := s.T()
			be, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("GetBackend() error = %v", err)
			}
			ingestedPkg, err := be.IngestSource(ctx, *tt.srcInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.IngestSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.idInFilter {
				tt.srcFilter.ID = &ingestedPkg.Namespaces[0].Names[0].ID
			}
			got, err := be.Sources(ctx, tt.srcFilter)
			if (err != nil) != tt.wantErr {
				t.Errorf("demoClient.Sources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
