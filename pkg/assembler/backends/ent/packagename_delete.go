// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// PackageNameDelete is the builder for deleting a PackageName entity.
type PackageNameDelete struct {
	config
	hooks    []Hook
	mutation *PackageNameMutation
}

// Where appends a list predicates to the PackageNameDelete builder.
func (pnd *PackageNameDelete) Where(ps ...predicate.PackageName) *PackageNameDelete {
	pnd.mutation.Where(ps...)
	return pnd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (pnd *PackageNameDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, pnd.sqlExec, pnd.mutation, pnd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (pnd *PackageNameDelete) ExecX(ctx context.Context) int {
	n, err := pnd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (pnd *PackageNameDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(packagename.Table, sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeInt))
	if ps := pnd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, pnd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	pnd.mutation.done = true
	return affected, err
}

// PackageNameDeleteOne is the builder for deleting a single PackageName entity.
type PackageNameDeleteOne struct {
	pnd *PackageNameDelete
}

// Where appends a list predicates to the PackageNameDelete builder.
func (pndo *PackageNameDeleteOne) Where(ps ...predicate.PackageName) *PackageNameDeleteOne {
	pndo.pnd.mutation.Where(ps...)
	return pndo
}

// Exec executes the deletion query.
func (pndo *PackageNameDeleteOne) Exec(ctx context.Context) error {
	n, err := pndo.pnd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{packagename.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (pndo *PackageNameDeleteOne) ExecX(ctx context.Context) {
	if err := pndo.Exec(ctx); err != nil {
		panic(err)
	}
}
