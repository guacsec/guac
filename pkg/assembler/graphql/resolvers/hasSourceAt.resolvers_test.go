package resolvers

import (
	"context"
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func Test_mutationResolver_IngestHasSourceAt(t *testing.T) {
	type fields struct {
		Resolver *Resolver
	}
	type args struct {
		ctx          context.Context
		pkg          model.PkgInputSpec
		pkgMatchType model.MatchFlags
		source       model.SourceInputSpec
		hasSourceAt  model.HasSourceAtInputSpec
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &mutationResolver{
				Resolver: tt.fields.Resolver,
			}
			got, err := r.IngestHasSourceAt(tt.args.ctx, tt.args.pkg, tt.args.pkgMatchType, tt.args.source, tt.args.hasSourceAt)
			if (err != nil) != tt.wantErr {
				t.Errorf("mutationResolver.IngestHasSourceAt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("mutationResolver.IngestHasSourceAt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_mutationResolver_IngestHasSourceAts(t *testing.T) {
	type fields struct {
		Resolver *Resolver
	}
	type args struct {
		ctx          context.Context
		pkgs         []*model.PkgInputSpec
		pkgMatchType model.MatchFlags
		sources      []*model.SourceInputSpec
		hasSourceAts []*model.HasSourceAtInputSpec
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &mutationResolver{
				Resolver: tt.fields.Resolver,
			}
			got, err := r.IngestHasSourceAts(tt.args.ctx, tt.args.pkgs, tt.args.pkgMatchType, tt.args.sources, tt.args.hasSourceAts)
			if (err != nil) != tt.wantErr {
				t.Errorf("mutationResolver.IngestHasSourceAts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mutationResolver.IngestHasSourceAts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_queryResolver_HasSourceAt(t *testing.T) {
	type fields struct {
		Resolver *Resolver
	}
	type args struct {
		ctx             context.Context
		hasSourceAtSpec model.HasSourceAtSpec
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*model.HasSourceAt
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &queryResolver{
				Resolver: tt.fields.Resolver,
			}
			got, err := r.HasSourceAt(tt.args.ctx, tt.args.hasSourceAtSpec)
			if (err != nil) != tt.wantErr {
				t.Errorf("queryResolver.HasSourceAt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("queryResolver.HasSourceAt() = %v, want %v", got, tt.want)
			}
		})
	}
}
