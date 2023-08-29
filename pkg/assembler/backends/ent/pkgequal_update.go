// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pkgequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// PkgEqualUpdate is the builder for updating PkgEqual entities.
type PkgEqualUpdate struct {
	config
	hooks    []Hook
	mutation *PkgEqualMutation
}

// Where appends a list predicates to the PkgEqualUpdate builder.
func (peu *PkgEqualUpdate) Where(ps ...predicate.PkgEqual) *PkgEqualUpdate {
	peu.mutation.Where(ps...)
	return peu
}

// SetOrigin sets the "origin" field.
func (peu *PkgEqualUpdate) SetOrigin(s string) *PkgEqualUpdate {
	peu.mutation.SetOrigin(s)
	return peu
}

// SetCollector sets the "collector" field.
func (peu *PkgEqualUpdate) SetCollector(s string) *PkgEqualUpdate {
	peu.mutation.SetCollector(s)
	return peu
}

// SetJustification sets the "justification" field.
func (peu *PkgEqualUpdate) SetJustification(s string) *PkgEqualUpdate {
	peu.mutation.SetJustification(s)
	return peu
}

// SetPackagesHash sets the "packages_hash" field.
func (peu *PkgEqualUpdate) SetPackagesHash(s string) *PkgEqualUpdate {
	peu.mutation.SetPackagesHash(s)
	return peu
}

// AddPackageIDs adds the "packages" edge to the PackageVersion entity by IDs.
func (peu *PkgEqualUpdate) AddPackageIDs(ids ...int) *PkgEqualUpdate {
	peu.mutation.AddPackageIDs(ids...)
	return peu
}

// AddPackages adds the "packages" edges to the PackageVersion entity.
func (peu *PkgEqualUpdate) AddPackages(p ...*PackageVersion) *PkgEqualUpdate {
	ids := make([]int, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return peu.AddPackageIDs(ids...)
}

// Mutation returns the PkgEqualMutation object of the builder.
func (peu *PkgEqualUpdate) Mutation() *PkgEqualMutation {
	return peu.mutation
}

// ClearPackages clears all "packages" edges to the PackageVersion entity.
func (peu *PkgEqualUpdate) ClearPackages() *PkgEqualUpdate {
	peu.mutation.ClearPackages()
	return peu
}

// RemovePackageIDs removes the "packages" edge to PackageVersion entities by IDs.
func (peu *PkgEqualUpdate) RemovePackageIDs(ids ...int) *PkgEqualUpdate {
	peu.mutation.RemovePackageIDs(ids...)
	return peu
}

// RemovePackages removes "packages" edges to PackageVersion entities.
func (peu *PkgEqualUpdate) RemovePackages(p ...*PackageVersion) *PkgEqualUpdate {
	ids := make([]int, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return peu.RemovePackageIDs(ids...)
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (peu *PkgEqualUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, peu.sqlSave, peu.mutation, peu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (peu *PkgEqualUpdate) SaveX(ctx context.Context) int {
	affected, err := peu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (peu *PkgEqualUpdate) Exec(ctx context.Context) error {
	_, err := peu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (peu *PkgEqualUpdate) ExecX(ctx context.Context) {
	if err := peu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (peu *PkgEqualUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(pkgequal.Table, pkgequal.Columns, sqlgraph.NewFieldSpec(pkgequal.FieldID, field.TypeInt))
	if ps := peu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := peu.mutation.Origin(); ok {
		_spec.SetField(pkgequal.FieldOrigin, field.TypeString, value)
	}
	if value, ok := peu.mutation.Collector(); ok {
		_spec.SetField(pkgequal.FieldCollector, field.TypeString, value)
	}
	if value, ok := peu.mutation.Justification(); ok {
		_spec.SetField(pkgequal.FieldJustification, field.TypeString, value)
	}
	if value, ok := peu.mutation.PackagesHash(); ok {
		_spec.SetField(pkgequal.FieldPackagesHash, field.TypeString, value)
	}
	if peu.mutation.PackagesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   pkgequal.PackagesTable,
			Columns: pkgequal.PackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := peu.mutation.RemovedPackagesIDs(); len(nodes) > 0 && !peu.mutation.PackagesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   pkgequal.PackagesTable,
			Columns: pkgequal.PackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := peu.mutation.PackagesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   pkgequal.PackagesTable,
			Columns: pkgequal.PackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, peu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{pkgequal.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	peu.mutation.done = true
	return n, nil
}

// PkgEqualUpdateOne is the builder for updating a single PkgEqual entity.
type PkgEqualUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *PkgEqualMutation
}

// SetOrigin sets the "origin" field.
func (peuo *PkgEqualUpdateOne) SetOrigin(s string) *PkgEqualUpdateOne {
	peuo.mutation.SetOrigin(s)
	return peuo
}

// SetCollector sets the "collector" field.
func (peuo *PkgEqualUpdateOne) SetCollector(s string) *PkgEqualUpdateOne {
	peuo.mutation.SetCollector(s)
	return peuo
}

// SetJustification sets the "justification" field.
func (peuo *PkgEqualUpdateOne) SetJustification(s string) *PkgEqualUpdateOne {
	peuo.mutation.SetJustification(s)
	return peuo
}

// SetPackagesHash sets the "packages_hash" field.
func (peuo *PkgEqualUpdateOne) SetPackagesHash(s string) *PkgEqualUpdateOne {
	peuo.mutation.SetPackagesHash(s)
	return peuo
}

// AddPackageIDs adds the "packages" edge to the PackageVersion entity by IDs.
func (peuo *PkgEqualUpdateOne) AddPackageIDs(ids ...int) *PkgEqualUpdateOne {
	peuo.mutation.AddPackageIDs(ids...)
	return peuo
}

// AddPackages adds the "packages" edges to the PackageVersion entity.
func (peuo *PkgEqualUpdateOne) AddPackages(p ...*PackageVersion) *PkgEqualUpdateOne {
	ids := make([]int, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return peuo.AddPackageIDs(ids...)
}

// Mutation returns the PkgEqualMutation object of the builder.
func (peuo *PkgEqualUpdateOne) Mutation() *PkgEqualMutation {
	return peuo.mutation
}

// ClearPackages clears all "packages" edges to the PackageVersion entity.
func (peuo *PkgEqualUpdateOne) ClearPackages() *PkgEqualUpdateOne {
	peuo.mutation.ClearPackages()
	return peuo
}

// RemovePackageIDs removes the "packages" edge to PackageVersion entities by IDs.
func (peuo *PkgEqualUpdateOne) RemovePackageIDs(ids ...int) *PkgEqualUpdateOne {
	peuo.mutation.RemovePackageIDs(ids...)
	return peuo
}

// RemovePackages removes "packages" edges to PackageVersion entities.
func (peuo *PkgEqualUpdateOne) RemovePackages(p ...*PackageVersion) *PkgEqualUpdateOne {
	ids := make([]int, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return peuo.RemovePackageIDs(ids...)
}

// Where appends a list predicates to the PkgEqualUpdate builder.
func (peuo *PkgEqualUpdateOne) Where(ps ...predicate.PkgEqual) *PkgEqualUpdateOne {
	peuo.mutation.Where(ps...)
	return peuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (peuo *PkgEqualUpdateOne) Select(field string, fields ...string) *PkgEqualUpdateOne {
	peuo.fields = append([]string{field}, fields...)
	return peuo
}

// Save executes the query and returns the updated PkgEqual entity.
func (peuo *PkgEqualUpdateOne) Save(ctx context.Context) (*PkgEqual, error) {
	return withHooks(ctx, peuo.sqlSave, peuo.mutation, peuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (peuo *PkgEqualUpdateOne) SaveX(ctx context.Context) *PkgEqual {
	node, err := peuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (peuo *PkgEqualUpdateOne) Exec(ctx context.Context) error {
	_, err := peuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (peuo *PkgEqualUpdateOne) ExecX(ctx context.Context) {
	if err := peuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (peuo *PkgEqualUpdateOne) sqlSave(ctx context.Context) (_node *PkgEqual, err error) {
	_spec := sqlgraph.NewUpdateSpec(pkgequal.Table, pkgequal.Columns, sqlgraph.NewFieldSpec(pkgequal.FieldID, field.TypeInt))
	id, ok := peuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "PkgEqual.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := peuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, pkgequal.FieldID)
		for _, f := range fields {
			if !pkgequal.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != pkgequal.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := peuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := peuo.mutation.Origin(); ok {
		_spec.SetField(pkgequal.FieldOrigin, field.TypeString, value)
	}
	if value, ok := peuo.mutation.Collector(); ok {
		_spec.SetField(pkgequal.FieldCollector, field.TypeString, value)
	}
	if value, ok := peuo.mutation.Justification(); ok {
		_spec.SetField(pkgequal.FieldJustification, field.TypeString, value)
	}
	if value, ok := peuo.mutation.PackagesHash(); ok {
		_spec.SetField(pkgequal.FieldPackagesHash, field.TypeString, value)
	}
	if peuo.mutation.PackagesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   pkgequal.PackagesTable,
			Columns: pkgequal.PackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := peuo.mutation.RemovedPackagesIDs(); len(nodes) > 0 && !peuo.mutation.PackagesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   pkgequal.PackagesTable,
			Columns: pkgequal.PackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := peuo.mutation.PackagesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   pkgequal.PackagesTable,
			Columns: pkgequal.PackagesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &PkgEqual{config: peuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, peuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{pkgequal.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	peuo.mutation.done = true
	return _node, nil
}
