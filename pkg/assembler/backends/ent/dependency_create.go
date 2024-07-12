// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/dependency"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
)

// DependencyCreate is the builder for creating a Dependency entity.
type DependencyCreate struct {
	config
	mutation *DependencyMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetPackageID sets the "package_id" field.
func (dc *DependencyCreate) SetPackageID(u uuid.UUID) *DependencyCreate {
	dc.mutation.SetPackageID(u)
	return dc
}

// SetDependentPackageVersionID sets the "dependent_package_version_id" field.
func (dc *DependencyCreate) SetDependentPackageVersionID(u uuid.UUID) *DependencyCreate {
	dc.mutation.SetDependentPackageVersionID(u)
	return dc
}

// SetNillableDependentPackageVersionID sets the "dependent_package_version_id" field if the given value is not nil.
func (dc *DependencyCreate) SetNillableDependentPackageVersionID(u *uuid.UUID) *DependencyCreate {
	if u != nil {
		dc.SetDependentPackageVersionID(*u)
	}
	return dc
}

// SetDependencyType sets the "dependency_type" field.
func (dc *DependencyCreate) SetDependencyType(dt dependency.DependencyType) *DependencyCreate {
	dc.mutation.SetDependencyType(dt)
	return dc
}

// SetJustification sets the "justification" field.
func (dc *DependencyCreate) SetJustification(s string) *DependencyCreate {
	dc.mutation.SetJustification(s)
	return dc
}

// SetOrigin sets the "origin" field.
func (dc *DependencyCreate) SetOrigin(s string) *DependencyCreate {
	dc.mutation.SetOrigin(s)
	return dc
}

// SetCollector sets the "collector" field.
func (dc *DependencyCreate) SetCollector(s string) *DependencyCreate {
	dc.mutation.SetCollector(s)
	return dc
}

// SetDocumentRef sets the "document_ref" field.
func (dc *DependencyCreate) SetDocumentRef(s string) *DependencyCreate {
	dc.mutation.SetDocumentRef(s)
	return dc
}

// SetID sets the "id" field.
func (dc *DependencyCreate) SetID(u uuid.UUID) *DependencyCreate {
	dc.mutation.SetID(u)
	return dc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (dc *DependencyCreate) SetNillableID(u *uuid.UUID) *DependencyCreate {
	if u != nil {
		dc.SetID(*u)
	}
	return dc
}

// SetPackage sets the "package" edge to the PackageVersion entity.
func (dc *DependencyCreate) SetPackage(p *PackageVersion) *DependencyCreate {
	return dc.SetPackageID(p.ID)
}

// SetDependentPackageVersion sets the "dependent_package_version" edge to the PackageVersion entity.
func (dc *DependencyCreate) SetDependentPackageVersion(p *PackageVersion) *DependencyCreate {
	return dc.SetDependentPackageVersionID(p.ID)
}

// AddIncludedInSbomIDs adds the "included_in_sboms" edge to the BillOfMaterials entity by IDs.
func (dc *DependencyCreate) AddIncludedInSbomIDs(ids ...uuid.UUID) *DependencyCreate {
	dc.mutation.AddIncludedInSbomIDs(ids...)
	return dc
}

// AddIncludedInSboms adds the "included_in_sboms" edges to the BillOfMaterials entity.
func (dc *DependencyCreate) AddIncludedInSboms(b ...*BillOfMaterials) *DependencyCreate {
	ids := make([]uuid.UUID, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return dc.AddIncludedInSbomIDs(ids...)
}

// Mutation returns the DependencyMutation object of the builder.
func (dc *DependencyCreate) Mutation() *DependencyMutation {
	return dc.mutation
}

// Save creates the Dependency in the database.
func (dc *DependencyCreate) Save(ctx context.Context) (*Dependency, error) {
	dc.defaults()
	return withHooks(ctx, dc.sqlSave, dc.mutation, dc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (dc *DependencyCreate) SaveX(ctx context.Context) *Dependency {
	v, err := dc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (dc *DependencyCreate) Exec(ctx context.Context) error {
	_, err := dc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dc *DependencyCreate) ExecX(ctx context.Context) {
	if err := dc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (dc *DependencyCreate) defaults() {
	if _, ok := dc.mutation.ID(); !ok {
		v := dependency.DefaultID()
		dc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (dc *DependencyCreate) check() error {
	if _, ok := dc.mutation.PackageID(); !ok {
		return &ValidationError{Name: "package_id", err: errors.New(`ent: missing required field "Dependency.package_id"`)}
	}
	if _, ok := dc.mutation.DependencyType(); !ok {
		return &ValidationError{Name: "dependency_type", err: errors.New(`ent: missing required field "Dependency.dependency_type"`)}
	}
	if v, ok := dc.mutation.DependencyType(); ok {
		if err := dependency.DependencyTypeValidator(v); err != nil {
			return &ValidationError{Name: "dependency_type", err: fmt.Errorf(`ent: validator failed for field "Dependency.dependency_type": %w`, err)}
		}
	}
	if _, ok := dc.mutation.Justification(); !ok {
		return &ValidationError{Name: "justification", err: errors.New(`ent: missing required field "Dependency.justification"`)}
	}
	if _, ok := dc.mutation.Origin(); !ok {
		return &ValidationError{Name: "origin", err: errors.New(`ent: missing required field "Dependency.origin"`)}
	}
	if _, ok := dc.mutation.Collector(); !ok {
		return &ValidationError{Name: "collector", err: errors.New(`ent: missing required field "Dependency.collector"`)}
	}
	if _, ok := dc.mutation.DocumentRef(); !ok {
		return &ValidationError{Name: "document_ref", err: errors.New(`ent: missing required field "Dependency.document_ref"`)}
	}
	if _, ok := dc.mutation.PackageID(); !ok {
		return &ValidationError{Name: "package", err: errors.New(`ent: missing required edge "Dependency.package"`)}
	}
	return nil
}

func (dc *DependencyCreate) sqlSave(ctx context.Context) (*Dependency, error) {
	if err := dc.check(); err != nil {
		return nil, err
	}
	_node, _spec := dc.createSpec()
	if err := sqlgraph.CreateNode(ctx, dc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(*uuid.UUID); ok {
			_node.ID = *id
		} else if err := _node.ID.Scan(_spec.ID.Value); err != nil {
			return nil, err
		}
	}
	dc.mutation.id = &_node.ID
	dc.mutation.done = true
	return _node, nil
}

func (dc *DependencyCreate) createSpec() (*Dependency, *sqlgraph.CreateSpec) {
	var (
		_node = &Dependency{config: dc.config}
		_spec = sqlgraph.NewCreateSpec(dependency.Table, sqlgraph.NewFieldSpec(dependency.FieldID, field.TypeUUID))
	)
	_spec.OnConflict = dc.conflict
	if id, ok := dc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := dc.mutation.DependencyType(); ok {
		_spec.SetField(dependency.FieldDependencyType, field.TypeEnum, value)
		_node.DependencyType = value
	}
	if value, ok := dc.mutation.Justification(); ok {
		_spec.SetField(dependency.FieldJustification, field.TypeString, value)
		_node.Justification = value
	}
	if value, ok := dc.mutation.Origin(); ok {
		_spec.SetField(dependency.FieldOrigin, field.TypeString, value)
		_node.Origin = value
	}
	if value, ok := dc.mutation.Collector(); ok {
		_spec.SetField(dependency.FieldCollector, field.TypeString, value)
		_node.Collector = value
	}
	if value, ok := dc.mutation.DocumentRef(); ok {
		_spec.SetField(dependency.FieldDocumentRef, field.TypeString, value)
		_node.DocumentRef = value
	}
	if nodes := dc.mutation.PackageIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.PackageTable,
			Columns: []string{dependency.PackageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.PackageID = nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := dc.mutation.DependentPackageVersionIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   dependency.DependentPackageVersionTable,
			Columns: []string{dependency.DependentPackageVersionColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.DependentPackageVersionID = nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := dc.mutation.IncludedInSbomsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   dependency.IncludedInSbomsTable,
			Columns: dependency.IncludedInSbomsPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Dependency.Create().
//		SetPackageID(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.DependencyUpsert) {
//			SetPackageID(v+v).
//		}).
//		Exec(ctx)
func (dc *DependencyCreate) OnConflict(opts ...sql.ConflictOption) *DependencyUpsertOne {
	dc.conflict = opts
	return &DependencyUpsertOne{
		create: dc,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Dependency.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (dc *DependencyCreate) OnConflictColumns(columns ...string) *DependencyUpsertOne {
	dc.conflict = append(dc.conflict, sql.ConflictColumns(columns...))
	return &DependencyUpsertOne{
		create: dc,
	}
}

type (
	// DependencyUpsertOne is the builder for "upsert"-ing
	//  one Dependency node.
	DependencyUpsertOne struct {
		create *DependencyCreate
	}

	// DependencyUpsert is the "OnConflict" setter.
	DependencyUpsert struct {
		*sql.UpdateSet
	}
)

// SetPackageID sets the "package_id" field.
func (u *DependencyUpsert) SetPackageID(v uuid.UUID) *DependencyUpsert {
	u.Set(dependency.FieldPackageID, v)
	return u
}

// UpdatePackageID sets the "package_id" field to the value that was provided on create.
func (u *DependencyUpsert) UpdatePackageID() *DependencyUpsert {
	u.SetExcluded(dependency.FieldPackageID)
	return u
}

// SetDependentPackageVersionID sets the "dependent_package_version_id" field.
func (u *DependencyUpsert) SetDependentPackageVersionID(v uuid.UUID) *DependencyUpsert {
	u.Set(dependency.FieldDependentPackageVersionID, v)
	return u
}

// UpdateDependentPackageVersionID sets the "dependent_package_version_id" field to the value that was provided on create.
func (u *DependencyUpsert) UpdateDependentPackageVersionID() *DependencyUpsert {
	u.SetExcluded(dependency.FieldDependentPackageVersionID)
	return u
}

// ClearDependentPackageVersionID clears the value of the "dependent_package_version_id" field.
func (u *DependencyUpsert) ClearDependentPackageVersionID() *DependencyUpsert {
	u.SetNull(dependency.FieldDependentPackageVersionID)
	return u
}

// SetDependencyType sets the "dependency_type" field.
func (u *DependencyUpsert) SetDependencyType(v dependency.DependencyType) *DependencyUpsert {
	u.Set(dependency.FieldDependencyType, v)
	return u
}

// UpdateDependencyType sets the "dependency_type" field to the value that was provided on create.
func (u *DependencyUpsert) UpdateDependencyType() *DependencyUpsert {
	u.SetExcluded(dependency.FieldDependencyType)
	return u
}

// SetJustification sets the "justification" field.
func (u *DependencyUpsert) SetJustification(v string) *DependencyUpsert {
	u.Set(dependency.FieldJustification, v)
	return u
}

// UpdateJustification sets the "justification" field to the value that was provided on create.
func (u *DependencyUpsert) UpdateJustification() *DependencyUpsert {
	u.SetExcluded(dependency.FieldJustification)
	return u
}

// SetOrigin sets the "origin" field.
func (u *DependencyUpsert) SetOrigin(v string) *DependencyUpsert {
	u.Set(dependency.FieldOrigin, v)
	return u
}

// UpdateOrigin sets the "origin" field to the value that was provided on create.
func (u *DependencyUpsert) UpdateOrigin() *DependencyUpsert {
	u.SetExcluded(dependency.FieldOrigin)
	return u
}

// SetCollector sets the "collector" field.
func (u *DependencyUpsert) SetCollector(v string) *DependencyUpsert {
	u.Set(dependency.FieldCollector, v)
	return u
}

// UpdateCollector sets the "collector" field to the value that was provided on create.
func (u *DependencyUpsert) UpdateCollector() *DependencyUpsert {
	u.SetExcluded(dependency.FieldCollector)
	return u
}

// SetDocumentRef sets the "document_ref" field.
func (u *DependencyUpsert) SetDocumentRef(v string) *DependencyUpsert {
	u.Set(dependency.FieldDocumentRef, v)
	return u
}

// UpdateDocumentRef sets the "document_ref" field to the value that was provided on create.
func (u *DependencyUpsert) UpdateDocumentRef() *DependencyUpsert {
	u.SetExcluded(dependency.FieldDocumentRef)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create except the ID field.
// Using this option is equivalent to using:
//
//	client.Dependency.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(dependency.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *DependencyUpsertOne) UpdateNewValues() *DependencyUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		if _, exists := u.create.mutation.ID(); exists {
			s.SetIgnore(dependency.FieldID)
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Dependency.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *DependencyUpsertOne) Ignore() *DependencyUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *DependencyUpsertOne) DoNothing() *DependencyUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the DependencyCreate.OnConflict
// documentation for more info.
func (u *DependencyUpsertOne) Update(set func(*DependencyUpsert)) *DependencyUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&DependencyUpsert{UpdateSet: update})
	}))
	return u
}

// SetPackageID sets the "package_id" field.
func (u *DependencyUpsertOne) SetPackageID(v uuid.UUID) *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.SetPackageID(v)
	})
}

// UpdatePackageID sets the "package_id" field to the value that was provided on create.
func (u *DependencyUpsertOne) UpdatePackageID() *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdatePackageID()
	})
}

// SetDependentPackageVersionID sets the "dependent_package_version_id" field.
func (u *DependencyUpsertOne) SetDependentPackageVersionID(v uuid.UUID) *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.SetDependentPackageVersionID(v)
	})
}

// UpdateDependentPackageVersionID sets the "dependent_package_version_id" field to the value that was provided on create.
func (u *DependencyUpsertOne) UpdateDependentPackageVersionID() *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdateDependentPackageVersionID()
	})
}

// ClearDependentPackageVersionID clears the value of the "dependent_package_version_id" field.
func (u *DependencyUpsertOne) ClearDependentPackageVersionID() *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.ClearDependentPackageVersionID()
	})
}

// SetDependencyType sets the "dependency_type" field.
func (u *DependencyUpsertOne) SetDependencyType(v dependency.DependencyType) *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.SetDependencyType(v)
	})
}

// UpdateDependencyType sets the "dependency_type" field to the value that was provided on create.
func (u *DependencyUpsertOne) UpdateDependencyType() *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdateDependencyType()
	})
}

// SetJustification sets the "justification" field.
func (u *DependencyUpsertOne) SetJustification(v string) *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.SetJustification(v)
	})
}

// UpdateJustification sets the "justification" field to the value that was provided on create.
func (u *DependencyUpsertOne) UpdateJustification() *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdateJustification()
	})
}

// SetOrigin sets the "origin" field.
func (u *DependencyUpsertOne) SetOrigin(v string) *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.SetOrigin(v)
	})
}

// UpdateOrigin sets the "origin" field to the value that was provided on create.
func (u *DependencyUpsertOne) UpdateOrigin() *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdateOrigin()
	})
}

// SetCollector sets the "collector" field.
func (u *DependencyUpsertOne) SetCollector(v string) *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.SetCollector(v)
	})
}

// UpdateCollector sets the "collector" field to the value that was provided on create.
func (u *DependencyUpsertOne) UpdateCollector() *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdateCollector()
	})
}

// SetDocumentRef sets the "document_ref" field.
func (u *DependencyUpsertOne) SetDocumentRef(v string) *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.SetDocumentRef(v)
	})
}

// UpdateDocumentRef sets the "document_ref" field to the value that was provided on create.
func (u *DependencyUpsertOne) UpdateDocumentRef() *DependencyUpsertOne {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdateDocumentRef()
	})
}

// Exec executes the query.
func (u *DependencyUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for DependencyCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *DependencyUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *DependencyUpsertOne) ID(ctx context.Context) (id uuid.UUID, err error) {
	if u.create.driver.Dialect() == dialect.MySQL {
		// In case of "ON CONFLICT", there is no way to get back non-numeric ID
		// fields from the database since MySQL does not support the RETURNING clause.
		return id, errors.New("ent: DependencyUpsertOne.ID is not supported by MySQL driver. Use DependencyUpsertOne.Exec instead")
	}
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *DependencyUpsertOne) IDX(ctx context.Context) uuid.UUID {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// DependencyCreateBulk is the builder for creating many Dependency entities in bulk.
type DependencyCreateBulk struct {
	config
	err      error
	builders []*DependencyCreate
	conflict []sql.ConflictOption
}

// Save creates the Dependency entities in the database.
func (dcb *DependencyCreateBulk) Save(ctx context.Context) ([]*Dependency, error) {
	if dcb.err != nil {
		return nil, dcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(dcb.builders))
	nodes := make([]*Dependency, len(dcb.builders))
	mutators := make([]Mutator, len(dcb.builders))
	for i := range dcb.builders {
		func(i int, root context.Context) {
			builder := dcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*DependencyMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, dcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = dcb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, dcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, dcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (dcb *DependencyCreateBulk) SaveX(ctx context.Context) []*Dependency {
	v, err := dcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (dcb *DependencyCreateBulk) Exec(ctx context.Context) error {
	_, err := dcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dcb *DependencyCreateBulk) ExecX(ctx context.Context) {
	if err := dcb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Dependency.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.DependencyUpsert) {
//			SetPackageID(v+v).
//		}).
//		Exec(ctx)
func (dcb *DependencyCreateBulk) OnConflict(opts ...sql.ConflictOption) *DependencyUpsertBulk {
	dcb.conflict = opts
	return &DependencyUpsertBulk{
		create: dcb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Dependency.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (dcb *DependencyCreateBulk) OnConflictColumns(columns ...string) *DependencyUpsertBulk {
	dcb.conflict = append(dcb.conflict, sql.ConflictColumns(columns...))
	return &DependencyUpsertBulk{
		create: dcb,
	}
}

// DependencyUpsertBulk is the builder for "upsert"-ing
// a bulk of Dependency nodes.
type DependencyUpsertBulk struct {
	create *DependencyCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.Dependency.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(dependency.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *DependencyUpsertBulk) UpdateNewValues() *DependencyUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		for _, b := range u.create.builders {
			if _, exists := b.mutation.ID(); exists {
				s.SetIgnore(dependency.FieldID)
			}
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Dependency.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *DependencyUpsertBulk) Ignore() *DependencyUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *DependencyUpsertBulk) DoNothing() *DependencyUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the DependencyCreateBulk.OnConflict
// documentation for more info.
func (u *DependencyUpsertBulk) Update(set func(*DependencyUpsert)) *DependencyUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&DependencyUpsert{UpdateSet: update})
	}))
	return u
}

// SetPackageID sets the "package_id" field.
func (u *DependencyUpsertBulk) SetPackageID(v uuid.UUID) *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.SetPackageID(v)
	})
}

// UpdatePackageID sets the "package_id" field to the value that was provided on create.
func (u *DependencyUpsertBulk) UpdatePackageID() *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdatePackageID()
	})
}

// SetDependentPackageVersionID sets the "dependent_package_version_id" field.
func (u *DependencyUpsertBulk) SetDependentPackageVersionID(v uuid.UUID) *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.SetDependentPackageVersionID(v)
	})
}

// UpdateDependentPackageVersionID sets the "dependent_package_version_id" field to the value that was provided on create.
func (u *DependencyUpsertBulk) UpdateDependentPackageVersionID() *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdateDependentPackageVersionID()
	})
}

// ClearDependentPackageVersionID clears the value of the "dependent_package_version_id" field.
func (u *DependencyUpsertBulk) ClearDependentPackageVersionID() *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.ClearDependentPackageVersionID()
	})
}

// SetDependencyType sets the "dependency_type" field.
func (u *DependencyUpsertBulk) SetDependencyType(v dependency.DependencyType) *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.SetDependencyType(v)
	})
}

// UpdateDependencyType sets the "dependency_type" field to the value that was provided on create.
func (u *DependencyUpsertBulk) UpdateDependencyType() *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdateDependencyType()
	})
}

// SetJustification sets the "justification" field.
func (u *DependencyUpsertBulk) SetJustification(v string) *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.SetJustification(v)
	})
}

// UpdateJustification sets the "justification" field to the value that was provided on create.
func (u *DependencyUpsertBulk) UpdateJustification() *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdateJustification()
	})
}

// SetOrigin sets the "origin" field.
func (u *DependencyUpsertBulk) SetOrigin(v string) *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.SetOrigin(v)
	})
}

// UpdateOrigin sets the "origin" field to the value that was provided on create.
func (u *DependencyUpsertBulk) UpdateOrigin() *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdateOrigin()
	})
}

// SetCollector sets the "collector" field.
func (u *DependencyUpsertBulk) SetCollector(v string) *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.SetCollector(v)
	})
}

// UpdateCollector sets the "collector" field to the value that was provided on create.
func (u *DependencyUpsertBulk) UpdateCollector() *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdateCollector()
	})
}

// SetDocumentRef sets the "document_ref" field.
func (u *DependencyUpsertBulk) SetDocumentRef(v string) *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.SetDocumentRef(v)
	})
}

// UpdateDocumentRef sets the "document_ref" field to the value that was provided on create.
func (u *DependencyUpsertBulk) UpdateDocumentRef() *DependencyUpsertBulk {
	return u.Update(func(s *DependencyUpsert) {
		s.UpdateDocumentRef()
	})
}

// Exec executes the query.
func (u *DependencyUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the DependencyCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for DependencyCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *DependencyUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
