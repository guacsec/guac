// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
)

// ArtifactCreate is the builder for creating a Artifact entity.
type ArtifactCreate struct {
	config
	mutation *ArtifactMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetAlgorithm sets the "algorithm" field.
func (ac *ArtifactCreate) SetAlgorithm(s string) *ArtifactCreate {
	ac.mutation.SetAlgorithm(s)
	return ac
}

// SetDigest sets the "digest" field.
func (ac *ArtifactCreate) SetDigest(s string) *ArtifactCreate {
	ac.mutation.SetDigest(s)
	return ac
}

// AddOccurrenceIDs adds the "occurrences" edge to the Occurrence entity by IDs.
func (ac *ArtifactCreate) AddOccurrenceIDs(ids ...int) *ArtifactCreate {
	ac.mutation.AddOccurrenceIDs(ids...)
	return ac
}

// AddOccurrences adds the "occurrences" edges to the Occurrence entity.
func (ac *ArtifactCreate) AddOccurrences(o ...*Occurrence) *ArtifactCreate {
	ids := make([]int, len(o))
	for i := range o {
		ids[i] = o[i].ID
	}
	return ac.AddOccurrenceIDs(ids...)
}

// AddSbomIDs adds the "sbom" edge to the BillOfMaterials entity by IDs.
func (ac *ArtifactCreate) AddSbomIDs(ids ...int) *ArtifactCreate {
	ac.mutation.AddSbomIDs(ids...)
	return ac
}

// AddSbom adds the "sbom" edges to the BillOfMaterials entity.
func (ac *ArtifactCreate) AddSbom(b ...*BillOfMaterials) *ArtifactCreate {
	ids := make([]int, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return ac.AddSbomIDs(ids...)
}

// Mutation returns the ArtifactMutation object of the builder.
func (ac *ArtifactCreate) Mutation() *ArtifactMutation {
	return ac.mutation
}

// Save creates the Artifact in the database.
func (ac *ArtifactCreate) Save(ctx context.Context) (*Artifact, error) {
	return withHooks(ctx, ac.sqlSave, ac.mutation, ac.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (ac *ArtifactCreate) SaveX(ctx context.Context) *Artifact {
	v, err := ac.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ac *ArtifactCreate) Exec(ctx context.Context) error {
	_, err := ac.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ac *ArtifactCreate) ExecX(ctx context.Context) {
	if err := ac.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ac *ArtifactCreate) check() error {
	if _, ok := ac.mutation.Algorithm(); !ok {
		return &ValidationError{Name: "algorithm", err: errors.New(`ent: missing required field "Artifact.algorithm"`)}
	}
	if _, ok := ac.mutation.Digest(); !ok {
		return &ValidationError{Name: "digest", err: errors.New(`ent: missing required field "Artifact.digest"`)}
	}
	return nil
}

func (ac *ArtifactCreate) sqlSave(ctx context.Context) (*Artifact, error) {
	if err := ac.check(); err != nil {
		return nil, err
	}
	_node, _spec := ac.createSpec()
	if err := sqlgraph.CreateNode(ctx, ac.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	ac.mutation.id = &_node.ID
	ac.mutation.done = true
	return _node, nil
}

func (ac *ArtifactCreate) createSpec() (*Artifact, *sqlgraph.CreateSpec) {
	var (
		_node = &Artifact{config: ac.config}
		_spec = sqlgraph.NewCreateSpec(artifact.Table, sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeInt))
	)
	_spec.OnConflict = ac.conflict
	if value, ok := ac.mutation.Algorithm(); ok {
		_spec.SetField(artifact.FieldAlgorithm, field.TypeString, value)
		_node.Algorithm = value
	}
	if value, ok := ac.mutation.Digest(); ok {
		_spec.SetField(artifact.FieldDigest, field.TypeString, value)
		_node.Digest = value
	}
	if nodes := ac.mutation.OccurrencesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   artifact.OccurrencesTable,
			Columns: []string{artifact.OccurrencesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(occurrence.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ac.mutation.SbomIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   artifact.SbomTable,
			Columns: []string{artifact.SbomColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(billofmaterials.FieldID, field.TypeInt),
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
//	client.Artifact.Create().
//		SetAlgorithm(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.ArtifactUpsert) {
//			SetAlgorithm(v+v).
//		}).
//		Exec(ctx)
func (ac *ArtifactCreate) OnConflict(opts ...sql.ConflictOption) *ArtifactUpsertOne {
	ac.conflict = opts
	return &ArtifactUpsertOne{
		create: ac,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Artifact.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (ac *ArtifactCreate) OnConflictColumns(columns ...string) *ArtifactUpsertOne {
	ac.conflict = append(ac.conflict, sql.ConflictColumns(columns...))
	return &ArtifactUpsertOne{
		create: ac,
	}
}

type (
	// ArtifactUpsertOne is the builder for "upsert"-ing
	//  one Artifact node.
	ArtifactUpsertOne struct {
		create *ArtifactCreate
	}

	// ArtifactUpsert is the "OnConflict" setter.
	ArtifactUpsert struct {
		*sql.UpdateSet
	}
)

// SetAlgorithm sets the "algorithm" field.
func (u *ArtifactUpsert) SetAlgorithm(v string) *ArtifactUpsert {
	u.Set(artifact.FieldAlgorithm, v)
	return u
}

// UpdateAlgorithm sets the "algorithm" field to the value that was provided on create.
func (u *ArtifactUpsert) UpdateAlgorithm() *ArtifactUpsert {
	u.SetExcluded(artifact.FieldAlgorithm)
	return u
}

// SetDigest sets the "digest" field.
func (u *ArtifactUpsert) SetDigest(v string) *ArtifactUpsert {
	u.Set(artifact.FieldDigest, v)
	return u
}

// UpdateDigest sets the "digest" field to the value that was provided on create.
func (u *ArtifactUpsert) UpdateDigest() *ArtifactUpsert {
	u.SetExcluded(artifact.FieldDigest)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create.
// Using this option is equivalent to using:
//
//	client.Artifact.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//		).
//		Exec(ctx)
func (u *ArtifactUpsertOne) UpdateNewValues() *ArtifactUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Artifact.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *ArtifactUpsertOne) Ignore() *ArtifactUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *ArtifactUpsertOne) DoNothing() *ArtifactUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the ArtifactCreate.OnConflict
// documentation for more info.
func (u *ArtifactUpsertOne) Update(set func(*ArtifactUpsert)) *ArtifactUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&ArtifactUpsert{UpdateSet: update})
	}))
	return u
}

// SetAlgorithm sets the "algorithm" field.
func (u *ArtifactUpsertOne) SetAlgorithm(v string) *ArtifactUpsertOne {
	return u.Update(func(s *ArtifactUpsert) {
		s.SetAlgorithm(v)
	})
}

// UpdateAlgorithm sets the "algorithm" field to the value that was provided on create.
func (u *ArtifactUpsertOne) UpdateAlgorithm() *ArtifactUpsertOne {
	return u.Update(func(s *ArtifactUpsert) {
		s.UpdateAlgorithm()
	})
}

// SetDigest sets the "digest" field.
func (u *ArtifactUpsertOne) SetDigest(v string) *ArtifactUpsertOne {
	return u.Update(func(s *ArtifactUpsert) {
		s.SetDigest(v)
	})
}

// UpdateDigest sets the "digest" field to the value that was provided on create.
func (u *ArtifactUpsertOne) UpdateDigest() *ArtifactUpsertOne {
	return u.Update(func(s *ArtifactUpsert) {
		s.UpdateDigest()
	})
}

// Exec executes the query.
func (u *ArtifactUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for ArtifactCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *ArtifactUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *ArtifactUpsertOne) ID(ctx context.Context) (id int, err error) {
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *ArtifactUpsertOne) IDX(ctx context.Context) int {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// ArtifactCreateBulk is the builder for creating many Artifact entities in bulk.
type ArtifactCreateBulk struct {
	config
	builders []*ArtifactCreate
	conflict []sql.ConflictOption
}

// Save creates the Artifact entities in the database.
func (acb *ArtifactCreateBulk) Save(ctx context.Context) ([]*Artifact, error) {
	specs := make([]*sqlgraph.CreateSpec, len(acb.builders))
	nodes := make([]*Artifact, len(acb.builders))
	mutators := make([]Mutator, len(acb.builders))
	for i := range acb.builders {
		func(i int, root context.Context) {
			builder := acb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*ArtifactMutation)
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
					_, err = mutators[i+1].Mutate(root, acb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = acb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, acb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
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
		if _, err := mutators[0].Mutate(ctx, acb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (acb *ArtifactCreateBulk) SaveX(ctx context.Context) []*Artifact {
	v, err := acb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (acb *ArtifactCreateBulk) Exec(ctx context.Context) error {
	_, err := acb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (acb *ArtifactCreateBulk) ExecX(ctx context.Context) {
	if err := acb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Artifact.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.ArtifactUpsert) {
//			SetAlgorithm(v+v).
//		}).
//		Exec(ctx)
func (acb *ArtifactCreateBulk) OnConflict(opts ...sql.ConflictOption) *ArtifactUpsertBulk {
	acb.conflict = opts
	return &ArtifactUpsertBulk{
		create: acb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Artifact.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (acb *ArtifactCreateBulk) OnConflictColumns(columns ...string) *ArtifactUpsertBulk {
	acb.conflict = append(acb.conflict, sql.ConflictColumns(columns...))
	return &ArtifactUpsertBulk{
		create: acb,
	}
}

// ArtifactUpsertBulk is the builder for "upsert"-ing
// a bulk of Artifact nodes.
type ArtifactUpsertBulk struct {
	create *ArtifactCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.Artifact.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//		).
//		Exec(ctx)
func (u *ArtifactUpsertBulk) UpdateNewValues() *ArtifactUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Artifact.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *ArtifactUpsertBulk) Ignore() *ArtifactUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *ArtifactUpsertBulk) DoNothing() *ArtifactUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the ArtifactCreateBulk.OnConflict
// documentation for more info.
func (u *ArtifactUpsertBulk) Update(set func(*ArtifactUpsert)) *ArtifactUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&ArtifactUpsert{UpdateSet: update})
	}))
	return u
}

// SetAlgorithm sets the "algorithm" field.
func (u *ArtifactUpsertBulk) SetAlgorithm(v string) *ArtifactUpsertBulk {
	return u.Update(func(s *ArtifactUpsert) {
		s.SetAlgorithm(v)
	})
}

// UpdateAlgorithm sets the "algorithm" field to the value that was provided on create.
func (u *ArtifactUpsertBulk) UpdateAlgorithm() *ArtifactUpsertBulk {
	return u.Update(func(s *ArtifactUpsert) {
		s.UpdateAlgorithm()
	})
}

// SetDigest sets the "digest" field.
func (u *ArtifactUpsertBulk) SetDigest(v string) *ArtifactUpsertBulk {
	return u.Update(func(s *ArtifactUpsert) {
		s.SetDigest(v)
	})
}

// UpdateDigest sets the "digest" field to the value that was provided on create.
func (u *ArtifactUpsertBulk) UpdateDigest() *ArtifactUpsertBulk {
	return u.Update(func(s *ArtifactUpsert) {
		s.UpdateDigest()
	})
}

// Exec executes the query.
func (u *ArtifactUpsertBulk) Exec(ctx context.Context) error {
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the ArtifactCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for ArtifactCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *ArtifactUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
