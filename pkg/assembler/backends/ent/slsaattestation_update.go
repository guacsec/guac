// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/dialect/sql/sqljson"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/builder"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/slsaattestation"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// SLSAAttestationUpdate is the builder for updating SLSAAttestation entities.
type SLSAAttestationUpdate struct {
	config
	hooks    []Hook
	mutation *SLSAAttestationMutation
}

// Where appends a list predicates to the SLSAAttestationUpdate builder.
func (sau *SLSAAttestationUpdate) Where(ps ...predicate.SLSAAttestation) *SLSAAttestationUpdate {
	sau.mutation.Where(ps...)
	return sau
}

// SetBuildType sets the "build_type" field.
func (sau *SLSAAttestationUpdate) SetBuildType(s string) *SLSAAttestationUpdate {
	sau.mutation.SetBuildType(s)
	return sau
}

// SetSlsaPredicate sets the "slsa_predicate" field.
func (sau *SLSAAttestationUpdate) SetSlsaPredicate(mp []*model.SLSAPredicate) *SLSAAttestationUpdate {
	sau.mutation.SetSlsaPredicate(mp)
	return sau
}

// AppendSlsaPredicate appends mp to the "slsa_predicate" field.
func (sau *SLSAAttestationUpdate) AppendSlsaPredicate(mp []*model.SLSAPredicate) *SLSAAttestationUpdate {
	sau.mutation.AppendSlsaPredicate(mp)
	return sau
}

// ClearSlsaPredicate clears the value of the "slsa_predicate" field.
func (sau *SLSAAttestationUpdate) ClearSlsaPredicate() *SLSAAttestationUpdate {
	sau.mutation.ClearSlsaPredicate()
	return sau
}

// SetSlsaVersion sets the "slsa_version" field.
func (sau *SLSAAttestationUpdate) SetSlsaVersion(s string) *SLSAAttestationUpdate {
	sau.mutation.SetSlsaVersion(s)
	return sau
}

// SetStartedOn sets the "started_on" field.
func (sau *SLSAAttestationUpdate) SetStartedOn(t time.Time) *SLSAAttestationUpdate {
	sau.mutation.SetStartedOn(t)
	return sau
}

// SetNillableStartedOn sets the "started_on" field if the given value is not nil.
func (sau *SLSAAttestationUpdate) SetNillableStartedOn(t *time.Time) *SLSAAttestationUpdate {
	if t != nil {
		sau.SetStartedOn(*t)
	}
	return sau
}

// ClearStartedOn clears the value of the "started_on" field.
func (sau *SLSAAttestationUpdate) ClearStartedOn() *SLSAAttestationUpdate {
	sau.mutation.ClearStartedOn()
	return sau
}

// SetFinishedOn sets the "finished_on" field.
func (sau *SLSAAttestationUpdate) SetFinishedOn(t time.Time) *SLSAAttestationUpdate {
	sau.mutation.SetFinishedOn(t)
	return sau
}

// SetNillableFinishedOn sets the "finished_on" field if the given value is not nil.
func (sau *SLSAAttestationUpdate) SetNillableFinishedOn(t *time.Time) *SLSAAttestationUpdate {
	if t != nil {
		sau.SetFinishedOn(*t)
	}
	return sau
}

// ClearFinishedOn clears the value of the "finished_on" field.
func (sau *SLSAAttestationUpdate) ClearFinishedOn() *SLSAAttestationUpdate {
	sau.mutation.ClearFinishedOn()
	return sau
}

// SetOrigin sets the "origin" field.
func (sau *SLSAAttestationUpdate) SetOrigin(s string) *SLSAAttestationUpdate {
	sau.mutation.SetOrigin(s)
	return sau
}

// SetCollector sets the "collector" field.
func (sau *SLSAAttestationUpdate) SetCollector(s string) *SLSAAttestationUpdate {
	sau.mutation.SetCollector(s)
	return sau
}

// AddBuiltFromIDs adds the "built_from" edge to the Artifact entity by IDs.
func (sau *SLSAAttestationUpdate) AddBuiltFromIDs(ids ...int) *SLSAAttestationUpdate {
	sau.mutation.AddBuiltFromIDs(ids...)
	return sau
}

// AddBuiltFrom adds the "built_from" edges to the Artifact entity.
func (sau *SLSAAttestationUpdate) AddBuiltFrom(a ...*Artifact) *SLSAAttestationUpdate {
	ids := make([]int, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return sau.AddBuiltFromIDs(ids...)
}

// AddBuiltByIDs adds the "built_by" edge to the Builder entity by IDs.
func (sau *SLSAAttestationUpdate) AddBuiltByIDs(ids ...int) *SLSAAttestationUpdate {
	sau.mutation.AddBuiltByIDs(ids...)
	return sau
}

// AddBuiltBy adds the "built_by" edges to the Builder entity.
func (sau *SLSAAttestationUpdate) AddBuiltBy(b ...*Builder) *SLSAAttestationUpdate {
	ids := make([]int, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return sau.AddBuiltByIDs(ids...)
}

// Mutation returns the SLSAAttestationMutation object of the builder.
func (sau *SLSAAttestationUpdate) Mutation() *SLSAAttestationMutation {
	return sau.mutation
}

// ClearBuiltFrom clears all "built_from" edges to the Artifact entity.
func (sau *SLSAAttestationUpdate) ClearBuiltFrom() *SLSAAttestationUpdate {
	sau.mutation.ClearBuiltFrom()
	return sau
}

// RemoveBuiltFromIDs removes the "built_from" edge to Artifact entities by IDs.
func (sau *SLSAAttestationUpdate) RemoveBuiltFromIDs(ids ...int) *SLSAAttestationUpdate {
	sau.mutation.RemoveBuiltFromIDs(ids...)
	return sau
}

// RemoveBuiltFrom removes "built_from" edges to Artifact entities.
func (sau *SLSAAttestationUpdate) RemoveBuiltFrom(a ...*Artifact) *SLSAAttestationUpdate {
	ids := make([]int, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return sau.RemoveBuiltFromIDs(ids...)
}

// ClearBuiltBy clears all "built_by" edges to the Builder entity.
func (sau *SLSAAttestationUpdate) ClearBuiltBy() *SLSAAttestationUpdate {
	sau.mutation.ClearBuiltBy()
	return sau
}

// RemoveBuiltByIDs removes the "built_by" edge to Builder entities by IDs.
func (sau *SLSAAttestationUpdate) RemoveBuiltByIDs(ids ...int) *SLSAAttestationUpdate {
	sau.mutation.RemoveBuiltByIDs(ids...)
	return sau
}

// RemoveBuiltBy removes "built_by" edges to Builder entities.
func (sau *SLSAAttestationUpdate) RemoveBuiltBy(b ...*Builder) *SLSAAttestationUpdate {
	ids := make([]int, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return sau.RemoveBuiltByIDs(ids...)
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (sau *SLSAAttestationUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, sau.sqlSave, sau.mutation, sau.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (sau *SLSAAttestationUpdate) SaveX(ctx context.Context) int {
	affected, err := sau.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (sau *SLSAAttestationUpdate) Exec(ctx context.Context) error {
	_, err := sau.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (sau *SLSAAttestationUpdate) ExecX(ctx context.Context) {
	if err := sau.Exec(ctx); err != nil {
		panic(err)
	}
}

func (sau *SLSAAttestationUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(slsaattestation.Table, slsaattestation.Columns, sqlgraph.NewFieldSpec(slsaattestation.FieldID, field.TypeInt))
	if ps := sau.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := sau.mutation.BuildType(); ok {
		_spec.SetField(slsaattestation.FieldBuildType, field.TypeString, value)
	}
	if value, ok := sau.mutation.SlsaPredicate(); ok {
		_spec.SetField(slsaattestation.FieldSlsaPredicate, field.TypeJSON, value)
	}
	if value, ok := sau.mutation.AppendedSlsaPredicate(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, slsaattestation.FieldSlsaPredicate, value)
		})
	}
	if sau.mutation.SlsaPredicateCleared() {
		_spec.ClearField(slsaattestation.FieldSlsaPredicate, field.TypeJSON)
	}
	if value, ok := sau.mutation.SlsaVersion(); ok {
		_spec.SetField(slsaattestation.FieldSlsaVersion, field.TypeString, value)
	}
	if value, ok := sau.mutation.StartedOn(); ok {
		_spec.SetField(slsaattestation.FieldStartedOn, field.TypeTime, value)
	}
	if sau.mutation.StartedOnCleared() {
		_spec.ClearField(slsaattestation.FieldStartedOn, field.TypeTime)
	}
	if value, ok := sau.mutation.FinishedOn(); ok {
		_spec.SetField(slsaattestation.FieldFinishedOn, field.TypeTime, value)
	}
	if sau.mutation.FinishedOnCleared() {
		_spec.ClearField(slsaattestation.FieldFinishedOn, field.TypeTime)
	}
	if value, ok := sau.mutation.Origin(); ok {
		_spec.SetField(slsaattestation.FieldOrigin, field.TypeString, value)
	}
	if value, ok := sau.mutation.Collector(); ok {
		_spec.SetField(slsaattestation.FieldCollector, field.TypeString, value)
	}
	if sau.mutation.BuiltFromCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   slsaattestation.BuiltFromTable,
			Columns: []string{slsaattestation.BuiltFromColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := sau.mutation.RemovedBuiltFromIDs(); len(nodes) > 0 && !sau.mutation.BuiltFromCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   slsaattestation.BuiltFromTable,
			Columns: []string{slsaattestation.BuiltFromColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := sau.mutation.BuiltFromIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   slsaattestation.BuiltFromTable,
			Columns: []string{slsaattestation.BuiltFromColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if sau.mutation.BuiltByCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   slsaattestation.BuiltByTable,
			Columns: []string{slsaattestation.BuiltByColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(builder.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := sau.mutation.RemovedBuiltByIDs(); len(nodes) > 0 && !sau.mutation.BuiltByCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   slsaattestation.BuiltByTable,
			Columns: []string{slsaattestation.BuiltByColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(builder.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := sau.mutation.BuiltByIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   slsaattestation.BuiltByTable,
			Columns: []string{slsaattestation.BuiltByColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(builder.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, sau.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{slsaattestation.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	sau.mutation.done = true
	return n, nil
}

// SLSAAttestationUpdateOne is the builder for updating a single SLSAAttestation entity.
type SLSAAttestationUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *SLSAAttestationMutation
}

// SetBuildType sets the "build_type" field.
func (sauo *SLSAAttestationUpdateOne) SetBuildType(s string) *SLSAAttestationUpdateOne {
	sauo.mutation.SetBuildType(s)
	return sauo
}

// SetSlsaPredicate sets the "slsa_predicate" field.
func (sauo *SLSAAttestationUpdateOne) SetSlsaPredicate(mp []*model.SLSAPredicate) *SLSAAttestationUpdateOne {
	sauo.mutation.SetSlsaPredicate(mp)
	return sauo
}

// AppendSlsaPredicate appends mp to the "slsa_predicate" field.
func (sauo *SLSAAttestationUpdateOne) AppendSlsaPredicate(mp []*model.SLSAPredicate) *SLSAAttestationUpdateOne {
	sauo.mutation.AppendSlsaPredicate(mp)
	return sauo
}

// ClearSlsaPredicate clears the value of the "slsa_predicate" field.
func (sauo *SLSAAttestationUpdateOne) ClearSlsaPredicate() *SLSAAttestationUpdateOne {
	sauo.mutation.ClearSlsaPredicate()
	return sauo
}

// SetSlsaVersion sets the "slsa_version" field.
func (sauo *SLSAAttestationUpdateOne) SetSlsaVersion(s string) *SLSAAttestationUpdateOne {
	sauo.mutation.SetSlsaVersion(s)
	return sauo
}

// SetStartedOn sets the "started_on" field.
func (sauo *SLSAAttestationUpdateOne) SetStartedOn(t time.Time) *SLSAAttestationUpdateOne {
	sauo.mutation.SetStartedOn(t)
	return sauo
}

// SetNillableStartedOn sets the "started_on" field if the given value is not nil.
func (sauo *SLSAAttestationUpdateOne) SetNillableStartedOn(t *time.Time) *SLSAAttestationUpdateOne {
	if t != nil {
		sauo.SetStartedOn(*t)
	}
	return sauo
}

// ClearStartedOn clears the value of the "started_on" field.
func (sauo *SLSAAttestationUpdateOne) ClearStartedOn() *SLSAAttestationUpdateOne {
	sauo.mutation.ClearStartedOn()
	return sauo
}

// SetFinishedOn sets the "finished_on" field.
func (sauo *SLSAAttestationUpdateOne) SetFinishedOn(t time.Time) *SLSAAttestationUpdateOne {
	sauo.mutation.SetFinishedOn(t)
	return sauo
}

// SetNillableFinishedOn sets the "finished_on" field if the given value is not nil.
func (sauo *SLSAAttestationUpdateOne) SetNillableFinishedOn(t *time.Time) *SLSAAttestationUpdateOne {
	if t != nil {
		sauo.SetFinishedOn(*t)
	}
	return sauo
}

// ClearFinishedOn clears the value of the "finished_on" field.
func (sauo *SLSAAttestationUpdateOne) ClearFinishedOn() *SLSAAttestationUpdateOne {
	sauo.mutation.ClearFinishedOn()
	return sauo
}

// SetOrigin sets the "origin" field.
func (sauo *SLSAAttestationUpdateOne) SetOrigin(s string) *SLSAAttestationUpdateOne {
	sauo.mutation.SetOrigin(s)
	return sauo
}

// SetCollector sets the "collector" field.
func (sauo *SLSAAttestationUpdateOne) SetCollector(s string) *SLSAAttestationUpdateOne {
	sauo.mutation.SetCollector(s)
	return sauo
}

// AddBuiltFromIDs adds the "built_from" edge to the Artifact entity by IDs.
func (sauo *SLSAAttestationUpdateOne) AddBuiltFromIDs(ids ...int) *SLSAAttestationUpdateOne {
	sauo.mutation.AddBuiltFromIDs(ids...)
	return sauo
}

// AddBuiltFrom adds the "built_from" edges to the Artifact entity.
func (sauo *SLSAAttestationUpdateOne) AddBuiltFrom(a ...*Artifact) *SLSAAttestationUpdateOne {
	ids := make([]int, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return sauo.AddBuiltFromIDs(ids...)
}

// AddBuiltByIDs adds the "built_by" edge to the Builder entity by IDs.
func (sauo *SLSAAttestationUpdateOne) AddBuiltByIDs(ids ...int) *SLSAAttestationUpdateOne {
	sauo.mutation.AddBuiltByIDs(ids...)
	return sauo
}

// AddBuiltBy adds the "built_by" edges to the Builder entity.
func (sauo *SLSAAttestationUpdateOne) AddBuiltBy(b ...*Builder) *SLSAAttestationUpdateOne {
	ids := make([]int, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return sauo.AddBuiltByIDs(ids...)
}

// Mutation returns the SLSAAttestationMutation object of the builder.
func (sauo *SLSAAttestationUpdateOne) Mutation() *SLSAAttestationMutation {
	return sauo.mutation
}

// ClearBuiltFrom clears all "built_from" edges to the Artifact entity.
func (sauo *SLSAAttestationUpdateOne) ClearBuiltFrom() *SLSAAttestationUpdateOne {
	sauo.mutation.ClearBuiltFrom()
	return sauo
}

// RemoveBuiltFromIDs removes the "built_from" edge to Artifact entities by IDs.
func (sauo *SLSAAttestationUpdateOne) RemoveBuiltFromIDs(ids ...int) *SLSAAttestationUpdateOne {
	sauo.mutation.RemoveBuiltFromIDs(ids...)
	return sauo
}

// RemoveBuiltFrom removes "built_from" edges to Artifact entities.
func (sauo *SLSAAttestationUpdateOne) RemoveBuiltFrom(a ...*Artifact) *SLSAAttestationUpdateOne {
	ids := make([]int, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return sauo.RemoveBuiltFromIDs(ids...)
}

// ClearBuiltBy clears all "built_by" edges to the Builder entity.
func (sauo *SLSAAttestationUpdateOne) ClearBuiltBy() *SLSAAttestationUpdateOne {
	sauo.mutation.ClearBuiltBy()
	return sauo
}

// RemoveBuiltByIDs removes the "built_by" edge to Builder entities by IDs.
func (sauo *SLSAAttestationUpdateOne) RemoveBuiltByIDs(ids ...int) *SLSAAttestationUpdateOne {
	sauo.mutation.RemoveBuiltByIDs(ids...)
	return sauo
}

// RemoveBuiltBy removes "built_by" edges to Builder entities.
func (sauo *SLSAAttestationUpdateOne) RemoveBuiltBy(b ...*Builder) *SLSAAttestationUpdateOne {
	ids := make([]int, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return sauo.RemoveBuiltByIDs(ids...)
}

// Where appends a list predicates to the SLSAAttestationUpdate builder.
func (sauo *SLSAAttestationUpdateOne) Where(ps ...predicate.SLSAAttestation) *SLSAAttestationUpdateOne {
	sauo.mutation.Where(ps...)
	return sauo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (sauo *SLSAAttestationUpdateOne) Select(field string, fields ...string) *SLSAAttestationUpdateOne {
	sauo.fields = append([]string{field}, fields...)
	return sauo
}

// Save executes the query and returns the updated SLSAAttestation entity.
func (sauo *SLSAAttestationUpdateOne) Save(ctx context.Context) (*SLSAAttestation, error) {
	return withHooks(ctx, sauo.sqlSave, sauo.mutation, sauo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (sauo *SLSAAttestationUpdateOne) SaveX(ctx context.Context) *SLSAAttestation {
	node, err := sauo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (sauo *SLSAAttestationUpdateOne) Exec(ctx context.Context) error {
	_, err := sauo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (sauo *SLSAAttestationUpdateOne) ExecX(ctx context.Context) {
	if err := sauo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (sauo *SLSAAttestationUpdateOne) sqlSave(ctx context.Context) (_node *SLSAAttestation, err error) {
	_spec := sqlgraph.NewUpdateSpec(slsaattestation.Table, slsaattestation.Columns, sqlgraph.NewFieldSpec(slsaattestation.FieldID, field.TypeInt))
	id, ok := sauo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "SLSAAttestation.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := sauo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, slsaattestation.FieldID)
		for _, f := range fields {
			if !slsaattestation.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != slsaattestation.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := sauo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := sauo.mutation.BuildType(); ok {
		_spec.SetField(slsaattestation.FieldBuildType, field.TypeString, value)
	}
	if value, ok := sauo.mutation.SlsaPredicate(); ok {
		_spec.SetField(slsaattestation.FieldSlsaPredicate, field.TypeJSON, value)
	}
	if value, ok := sauo.mutation.AppendedSlsaPredicate(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, slsaattestation.FieldSlsaPredicate, value)
		})
	}
	if sauo.mutation.SlsaPredicateCleared() {
		_spec.ClearField(slsaattestation.FieldSlsaPredicate, field.TypeJSON)
	}
	if value, ok := sauo.mutation.SlsaVersion(); ok {
		_spec.SetField(slsaattestation.FieldSlsaVersion, field.TypeString, value)
	}
	if value, ok := sauo.mutation.StartedOn(); ok {
		_spec.SetField(slsaattestation.FieldStartedOn, field.TypeTime, value)
	}
	if sauo.mutation.StartedOnCleared() {
		_spec.ClearField(slsaattestation.FieldStartedOn, field.TypeTime)
	}
	if value, ok := sauo.mutation.FinishedOn(); ok {
		_spec.SetField(slsaattestation.FieldFinishedOn, field.TypeTime, value)
	}
	if sauo.mutation.FinishedOnCleared() {
		_spec.ClearField(slsaattestation.FieldFinishedOn, field.TypeTime)
	}
	if value, ok := sauo.mutation.Origin(); ok {
		_spec.SetField(slsaattestation.FieldOrigin, field.TypeString, value)
	}
	if value, ok := sauo.mutation.Collector(); ok {
		_spec.SetField(slsaattestation.FieldCollector, field.TypeString, value)
	}
	if sauo.mutation.BuiltFromCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   slsaattestation.BuiltFromTable,
			Columns: []string{slsaattestation.BuiltFromColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := sauo.mutation.RemovedBuiltFromIDs(); len(nodes) > 0 && !sauo.mutation.BuiltFromCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   slsaattestation.BuiltFromTable,
			Columns: []string{slsaattestation.BuiltFromColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := sauo.mutation.BuiltFromIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   slsaattestation.BuiltFromTable,
			Columns: []string{slsaattestation.BuiltFromColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if sauo.mutation.BuiltByCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   slsaattestation.BuiltByTable,
			Columns: []string{slsaattestation.BuiltByColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(builder.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := sauo.mutation.RemovedBuiltByIDs(); len(nodes) > 0 && !sauo.mutation.BuiltByCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   slsaattestation.BuiltByTable,
			Columns: []string{slsaattestation.BuiltByColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(builder.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := sauo.mutation.BuiltByIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   slsaattestation.BuiltByTable,
			Columns: []string{slsaattestation.BuiltByColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(builder.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &SLSAAttestation{config: sauo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, sauo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{slsaattestation.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	sauo.mutation.done = true
	return _node, nil
}
