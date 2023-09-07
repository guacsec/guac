// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// DependencyUpdate is the builder for updating Dependency entities.
type DependencyUpdate struct {
	config
	hooks    []Hook
	mutation *DependencyMutation
}

// Where appends a list predicates to the DependencyUpdate builder.
func (du *DependencyUpdate) Where(ps ...predicate.Dependency) *DependencyUpdate {
	du.mutation.Where(ps...)
	return du
}

// SetPackageID sets the "package_id" field.
func (du *DependencyUpdate) SetPackageID(i int) *DependencyUpdate {
	du.mutation.SetPackageID(i)
	return du
}

// SetDependentPackageNameID sets the "dependent_package_name_id" field.
func (du *DependencyUpdate) SetDependentPackageNameID(i int) *DependencyUpdate {
	du.mutation.SetDependentPackageNameID(i)
	return du
}

// SetNillableDependentPackageNameID sets the "dependent_package_name_id" field if the given value is not nil.
func (du *DependencyUpdate) SetNillableDependentPackageNameID(i *int) *DependencyUpdate {
	if i != nil {
		du.SetDependentPackageNameID(*i)
	}
	return du
}

// ClearDependentPackageNameID clears the value of the "dependent_package_name_id" field.
func (du *DependencyUpdate) ClearDependentPackageNameID() *DependencyUpdate {
	du.mutation.ClearDependentPackageNameID()
	return du
}

// SetDependentPackageVersionID sets the "dependent_package_version_id" field.
func (du *DependencyUpdate) SetDependentPackageVersionID(i int) *DependencyUpdate {
	du.mutation.SetDependentPackageVersionID(i)
	return du
}

// SetNillableDependentPackageVersionID sets the "dependent_package_version_id" field if the given value is not nil.
func (du *DependencyUpdate) SetNillableDependentPackageVersionID(i *int) *DependencyUpdate {
	if i != nil {
		du.SetDependentPackageVersionID(*i)
	}
	return du
}

// ClearDependentPackageVersionID clears the value of the "dependent_package_version_id" field.
func (du *DependencyUpdate) ClearDependentPackageVersionID() *DependencyUpdate {
	du.mutation.ClearDependentPackageVersionID()
	return du
}

// SetVersionRange sets the "version_range" field.
func (du *DependencyUpdate) SetVersionRange(s string) *DependencyUpdate {
	du.mutation.SetVersionRange(s)
	return du
}

// SetDependencyType sets the "dependency_type" field.
func (du *DependencyUpdate) SetDependencyType(dt dependency.DependencyType) *DependencyUpdate {
	du.mutation.SetDependencyType(dt)
	return du
}

// SetJustification sets the "justification" field.
func (du *DependencyUpdate) SetJustification(s string) *DependencyUpdate {
	du.mutation.SetJustification(s)
	return du
}

// SetOrigin sets the "origin" field.
func (du *DependencyUpdate) SetOrigin(s string) *DependencyUpdate {
	du.mutation.SetOrigin(s)
	return du
}

// SetCollector sets the "collector" field.
func (du *DependencyUpdate) SetCollector(s string) *DependencyUpdate {
	du.mutation.SetCollector(s)
	return du
}

// SetPackage sets the "package" edge to the PackageVersion entity.
func (du *DependencyUpdate) SetPackage(p *PackageVersion) *DependencyUpdate {
	return du.SetPackageID(p.ID)
}

// SetDependentPackageName sets the "dependent_package_name" edge to the PackageName entity.
func (du *DependencyUpdate) SetDependentPackageName(p *PackageName) *DependencyUpdate {
	return du.SetDependentPackageNameID(p.ID)
}

// SetDependentPackageVersion sets the "dependent_package_version" edge to the PackageVersion entity.
func (du *DependencyUpdate) SetDependentPackageVersion(p *PackageVersion) *DependencyUpdate {
	return du.SetDependentPackageVersionID(p.ID)
}

// Mutation returns the DependencyMutation object of the builder.
func (du *DependencyUpdate) Mutation() *DependencyMutation {
	return du.mutation
}

// ClearPackage clears the "package" edge to the PackageVersion entity.
func (du *DependencyUpdate) ClearPackage() *DependencyUpdate {
	du.mutation.ClearPackage()
	return du
}

// ClearDependentPackageName clears the "dependent_package_name" edge to the PackageName entity.
func (du *DependencyUpdate) ClearDependentPackageName() *DependencyUpdate {
	du.mutation.ClearDependentPackageName()
	return du
}

// ClearDependentPackageVersion clears the "dependent_package_version" edge to the PackageVersion entity.
func (du *DependencyUpdate) ClearDependentPackageVersion() *DependencyUpdate {
	du.mutation.ClearDependentPackageVersion()
	return du
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (du *DependencyUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, du.sqlSave, du.mutation, du.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (du *DependencyUpdate) SaveX(ctx context.Context) int {
	affected, err := du.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (du *DependencyUpdate) Exec(ctx context.Context) error {
	_, err := du.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (du *DependencyUpdate) ExecX(ctx context.Context) {
	if err := du.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (du *DependencyUpdate) check() error {
	if v, ok := du.mutation.DependencyType(); ok {
		if err := dependency.DependencyTypeValidator(v); err != nil {
			return &ValidationError{Name: "dependency_type", err: fmt.Errorf(`ent: validator failed for field "Dependency.dependency_type": %w`, err)}
		}
	}
	if _, ok := du.mutation.PackageID(); du.mutation.PackageCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "Dependency.package"`)
	}
	return nil
}

func (du *DependencyUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := du.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(dependency.Table, dependency.Columns, sqlgraph.NewFieldSpec(dependency.FieldID, field.TypeInt))
	if ps := du.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := du.mutation.VersionRange(); ok {
		_spec.SetField(dependency.FieldVersionRange, field.TypeString, value)
	}
	if value, ok := du.mutation.DependencyType(); ok {
		_spec.SetField(dependency.FieldDependencyType, field.TypeEnum, value)
	}
	if value, ok := du.mutation.Justification(); ok {
		_spec.SetField(dependency.FieldJustification, field.TypeString, value)
	}
	if value, ok := du.mutation.Origin(); ok {
		_spec.SetField(dependency.FieldOrigin, field.TypeString, value)
	}
	if value, ok := du.mutation.Collector(); ok {
		_spec.SetField(dependency.FieldCollector, field.TypeString, value)
	}
	if du.mutation.PackageCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.PackageTable,
			Columns: []string{dependency.PackageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := du.mutation.PackageIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.PackageTable,
			Columns: []string{dependency.PackageColumn},
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
	if du.mutation.DependentPackageNameCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.DependentPackageNameTable,
			Columns: []string{dependency.DependentPackageNameColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := du.mutation.DependentPackageNameIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.DependentPackageNameTable,
			Columns: []string{dependency.DependentPackageNameColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if du.mutation.DependentPackageVersionCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.DependentPackageVersionTable,
			Columns: []string{dependency.DependentPackageVersionColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := du.mutation.DependentPackageVersionIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.DependentPackageVersionTable,
			Columns: []string{dependency.DependentPackageVersionColumn},
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
	if n, err = sqlgraph.UpdateNodes(ctx, du.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{dependency.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	du.mutation.done = true
	return n, nil
}

// DependencyUpdateOne is the builder for updating a single Dependency entity.
type DependencyUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *DependencyMutation
}

// SetPackageID sets the "package_id" field.
func (duo *DependencyUpdateOne) SetPackageID(i int) *DependencyUpdateOne {
	duo.mutation.SetPackageID(i)
	return duo
}

// SetDependentPackageNameID sets the "dependent_package_name_id" field.
func (duo *DependencyUpdateOne) SetDependentPackageNameID(i int) *DependencyUpdateOne {
	duo.mutation.SetDependentPackageNameID(i)
	return duo
}

// SetNillableDependentPackageNameID sets the "dependent_package_name_id" field if the given value is not nil.
func (duo *DependencyUpdateOne) SetNillableDependentPackageNameID(i *int) *DependencyUpdateOne {
	if i != nil {
		duo.SetDependentPackageNameID(*i)
	}
	return duo
}

// ClearDependentPackageNameID clears the value of the "dependent_package_name_id" field.
func (duo *DependencyUpdateOne) ClearDependentPackageNameID() *DependencyUpdateOne {
	duo.mutation.ClearDependentPackageNameID()
	return duo
}

// SetDependentPackageVersionID sets the "dependent_package_version_id" field.
func (duo *DependencyUpdateOne) SetDependentPackageVersionID(i int) *DependencyUpdateOne {
	duo.mutation.SetDependentPackageVersionID(i)
	return duo
}

// SetNillableDependentPackageVersionID sets the "dependent_package_version_id" field if the given value is not nil.
func (duo *DependencyUpdateOne) SetNillableDependentPackageVersionID(i *int) *DependencyUpdateOne {
	if i != nil {
		duo.SetDependentPackageVersionID(*i)
	}
	return duo
}

// ClearDependentPackageVersionID clears the value of the "dependent_package_version_id" field.
func (duo *DependencyUpdateOne) ClearDependentPackageVersionID() *DependencyUpdateOne {
	duo.mutation.ClearDependentPackageVersionID()
	return duo
}

// SetVersionRange sets the "version_range" field.
func (duo *DependencyUpdateOne) SetVersionRange(s string) *DependencyUpdateOne {
	duo.mutation.SetVersionRange(s)
	return duo
}

// SetDependencyType sets the "dependency_type" field.
func (duo *DependencyUpdateOne) SetDependencyType(dt dependency.DependencyType) *DependencyUpdateOne {
	duo.mutation.SetDependencyType(dt)
	return duo
}

// SetJustification sets the "justification" field.
func (duo *DependencyUpdateOne) SetJustification(s string) *DependencyUpdateOne {
	duo.mutation.SetJustification(s)
	return duo
}

// SetOrigin sets the "origin" field.
func (duo *DependencyUpdateOne) SetOrigin(s string) *DependencyUpdateOne {
	duo.mutation.SetOrigin(s)
	return duo
}

// SetCollector sets the "collector" field.
func (duo *DependencyUpdateOne) SetCollector(s string) *DependencyUpdateOne {
	duo.mutation.SetCollector(s)
	return duo
}

// SetPackage sets the "package" edge to the PackageVersion entity.
func (duo *DependencyUpdateOne) SetPackage(p *PackageVersion) *DependencyUpdateOne {
	return duo.SetPackageID(p.ID)
}

// SetDependentPackageName sets the "dependent_package_name" edge to the PackageName entity.
func (duo *DependencyUpdateOne) SetDependentPackageName(p *PackageName) *DependencyUpdateOne {
	return duo.SetDependentPackageNameID(p.ID)
}

// SetDependentPackageVersion sets the "dependent_package_version" edge to the PackageVersion entity.
func (duo *DependencyUpdateOne) SetDependentPackageVersion(p *PackageVersion) *DependencyUpdateOne {
	return duo.SetDependentPackageVersionID(p.ID)
}

// Mutation returns the DependencyMutation object of the builder.
func (duo *DependencyUpdateOne) Mutation() *DependencyMutation {
	return duo.mutation
}

// ClearPackage clears the "package" edge to the PackageVersion entity.
func (duo *DependencyUpdateOne) ClearPackage() *DependencyUpdateOne {
	duo.mutation.ClearPackage()
	return duo
}

// ClearDependentPackageName clears the "dependent_package_name" edge to the PackageName entity.
func (duo *DependencyUpdateOne) ClearDependentPackageName() *DependencyUpdateOne {
	duo.mutation.ClearDependentPackageName()
	return duo
}

// ClearDependentPackageVersion clears the "dependent_package_version" edge to the PackageVersion entity.
func (duo *DependencyUpdateOne) ClearDependentPackageVersion() *DependencyUpdateOne {
	duo.mutation.ClearDependentPackageVersion()
	return duo
}

// Where appends a list predicates to the DependencyUpdate builder.
func (duo *DependencyUpdateOne) Where(ps ...predicate.Dependency) *DependencyUpdateOne {
	duo.mutation.Where(ps...)
	return duo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (duo *DependencyUpdateOne) Select(field string, fields ...string) *DependencyUpdateOne {
	duo.fields = append([]string{field}, fields...)
	return duo
}

// Save executes the query and returns the updated Dependency entity.
func (duo *DependencyUpdateOne) Save(ctx context.Context) (*Dependency, error) {
	return withHooks(ctx, duo.sqlSave, duo.mutation, duo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (duo *DependencyUpdateOne) SaveX(ctx context.Context) *Dependency {
	node, err := duo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (duo *DependencyUpdateOne) Exec(ctx context.Context) error {
	_, err := duo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (duo *DependencyUpdateOne) ExecX(ctx context.Context) {
	if err := duo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (duo *DependencyUpdateOne) check() error {
	if v, ok := duo.mutation.DependencyType(); ok {
		if err := dependency.DependencyTypeValidator(v); err != nil {
			return &ValidationError{Name: "dependency_type", err: fmt.Errorf(`ent: validator failed for field "Dependency.dependency_type": %w`, err)}
		}
	}
	if _, ok := duo.mutation.PackageID(); duo.mutation.PackageCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "Dependency.package"`)
	}
	return nil
}

func (duo *DependencyUpdateOne) sqlSave(ctx context.Context) (_node *Dependency, err error) {
	if err := duo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(dependency.Table, dependency.Columns, sqlgraph.NewFieldSpec(dependency.FieldID, field.TypeInt))
	id, ok := duo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Dependency.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := duo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, dependency.FieldID)
		for _, f := range fields {
			if !dependency.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != dependency.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := duo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := duo.mutation.VersionRange(); ok {
		_spec.SetField(dependency.FieldVersionRange, field.TypeString, value)
	}
	if value, ok := duo.mutation.DependencyType(); ok {
		_spec.SetField(dependency.FieldDependencyType, field.TypeEnum, value)
	}
	if value, ok := duo.mutation.Justification(); ok {
		_spec.SetField(dependency.FieldJustification, field.TypeString, value)
	}
	if value, ok := duo.mutation.Origin(); ok {
		_spec.SetField(dependency.FieldOrigin, field.TypeString, value)
	}
	if value, ok := duo.mutation.Collector(); ok {
		_spec.SetField(dependency.FieldCollector, field.TypeString, value)
	}
	if duo.mutation.PackageCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.PackageTable,
			Columns: []string{dependency.PackageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := duo.mutation.PackageIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.PackageTable,
			Columns: []string{dependency.PackageColumn},
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
	if duo.mutation.DependentPackageNameCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.DependentPackageNameTable,
			Columns: []string{dependency.DependentPackageNameColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := duo.mutation.DependentPackageNameIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.DependentPackageNameTable,
			Columns: []string{dependency.DependentPackageNameColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packagename.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if duo.mutation.DependentPackageVersionCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.DependentPackageVersionTable,
			Columns: []string{dependency.DependentPackageVersionColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := duo.mutation.DependentPackageVersionIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.DependentPackageVersionTable,
			Columns: []string{dependency.DependentPackageVersionColumn},
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
	_node = &Dependency{config: duo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, duo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{dependency.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	duo.mutation.done = true
	return _node, nil
}
