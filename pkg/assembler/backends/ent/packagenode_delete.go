// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagenode"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// PackageNodeDelete is the builder for deleting a PackageNode entity.
type PackageNodeDelete struct {
	config
	hooks    []Hook
	mutation *PackageNodeMutation
}

// Where appends a list predicates to the PackageNodeDelete builder.
func (pnd *PackageNodeDelete) Where(ps ...predicate.PackageNode) *PackageNodeDelete {
	pnd.mutation.Where(ps...)
	return pnd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (pnd *PackageNodeDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, pnd.sqlExec, pnd.mutation, pnd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (pnd *PackageNodeDelete) ExecX(ctx context.Context) int {
	n, err := pnd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (pnd *PackageNodeDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(packagenode.Table, sqlgraph.NewFieldSpec(packagenode.FieldID, field.TypeInt))
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

// PackageNodeDeleteOne is the builder for deleting a single PackageNode entity.
type PackageNodeDeleteOne struct {
	pnd *PackageNodeDelete
}

// Where appends a list predicates to the PackageNodeDelete builder.
func (pndo *PackageNodeDeleteOne) Where(ps ...predicate.PackageNode) *PackageNodeDeleteOne {
	pndo.pnd.mutation.Where(ps...)
	return pndo
}

// Exec executes the deletion query.
func (pndo *PackageNodeDeleteOne) Exec(ctx context.Context) error {
	n, err := pndo.pnd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{packagenode.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (pndo *PackageNodeDeleteOne) ExecX(ctx context.Context) {
	if err := pndo.Exec(ctx); err != nil {
		panic(err)
	}
}
