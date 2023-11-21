// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyscorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/scorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
)

// CertifyScorecardUpdate is the builder for updating CertifyScorecard entities.
type CertifyScorecardUpdate struct {
	config
	hooks    []Hook
	mutation *CertifyScorecardMutation
}

// Where appends a list predicates to the CertifyScorecardUpdate builder.
func (csu *CertifyScorecardUpdate) Where(ps ...predicate.CertifyScorecard) *CertifyScorecardUpdate {
	csu.mutation.Where(ps...)
	return csu
}

// SetSourceID sets the "source_id" field.
func (csu *CertifyScorecardUpdate) SetSourceID(i int) *CertifyScorecardUpdate {
	csu.mutation.SetSourceID(i)
	return csu
}

// SetNillableSourceID sets the "source_id" field if the given value is not nil.
func (csu *CertifyScorecardUpdate) SetNillableSourceID(i *int) *CertifyScorecardUpdate {
	if i != nil {
		csu.SetSourceID(*i)
	}
	return csu
}

// SetScorecardID sets the "scorecard_id" field.
func (csu *CertifyScorecardUpdate) SetScorecardID(i int) *CertifyScorecardUpdate {
	csu.mutation.SetScorecardID(i)
	return csu
}

// SetNillableScorecardID sets the "scorecard_id" field if the given value is not nil.
func (csu *CertifyScorecardUpdate) SetNillableScorecardID(i *int) *CertifyScorecardUpdate {
	if i != nil {
		csu.SetScorecardID(*i)
	}
	return csu
}

// SetScorecard sets the "scorecard" edge to the Scorecard entity.
func (csu *CertifyScorecardUpdate) SetScorecard(s *Scorecard) *CertifyScorecardUpdate {
	return csu.SetScorecardID(s.ID)
}

// SetSource sets the "source" edge to the SourceName entity.
func (csu *CertifyScorecardUpdate) SetSource(s *SourceName) *CertifyScorecardUpdate {
	return csu.SetSourceID(s.ID)
}

// Mutation returns the CertifyScorecardMutation object of the builder.
func (csu *CertifyScorecardUpdate) Mutation() *CertifyScorecardMutation {
	return csu.mutation
}

// ClearScorecard clears the "scorecard" edge to the Scorecard entity.
func (csu *CertifyScorecardUpdate) ClearScorecard() *CertifyScorecardUpdate {
	csu.mutation.ClearScorecard()
	return csu
}

// ClearSource clears the "source" edge to the SourceName entity.
func (csu *CertifyScorecardUpdate) ClearSource() *CertifyScorecardUpdate {
	csu.mutation.ClearSource()
	return csu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (csu *CertifyScorecardUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, csu.sqlSave, csu.mutation, csu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (csu *CertifyScorecardUpdate) SaveX(ctx context.Context) int {
	affected, err := csu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (csu *CertifyScorecardUpdate) Exec(ctx context.Context) error {
	_, err := csu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (csu *CertifyScorecardUpdate) ExecX(ctx context.Context) {
	if err := csu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (csu *CertifyScorecardUpdate) check() error {
	if _, ok := csu.mutation.ScorecardID(); csu.mutation.ScorecardCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "CertifyScorecard.scorecard"`)
	}
	if _, ok := csu.mutation.SourceID(); csu.mutation.SourceCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "CertifyScorecard.source"`)
	}
	return nil
}

func (csu *CertifyScorecardUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := csu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(certifyscorecard.Table, certifyscorecard.Columns, sqlgraph.NewFieldSpec(certifyscorecard.FieldID, field.TypeInt))
	if ps := csu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if csu.mutation.ScorecardCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   certifyscorecard.ScorecardTable,
			Columns: []string{certifyscorecard.ScorecardColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(scorecard.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := csu.mutation.ScorecardIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   certifyscorecard.ScorecardTable,
			Columns: []string{certifyscorecard.ScorecardColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(scorecard.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if csu.mutation.SourceCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyscorecard.SourceTable,
			Columns: []string{certifyscorecard.SourceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(sourcename.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := csu.mutation.SourceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyscorecard.SourceTable,
			Columns: []string{certifyscorecard.SourceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(sourcename.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, csu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{certifyscorecard.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	csu.mutation.done = true
	return n, nil
}

// CertifyScorecardUpdateOne is the builder for updating a single CertifyScorecard entity.
type CertifyScorecardUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *CertifyScorecardMutation
}

// SetSourceID sets the "source_id" field.
func (csuo *CertifyScorecardUpdateOne) SetSourceID(i int) *CertifyScorecardUpdateOne {
	csuo.mutation.SetSourceID(i)
	return csuo
}

// SetNillableSourceID sets the "source_id" field if the given value is not nil.
func (csuo *CertifyScorecardUpdateOne) SetNillableSourceID(i *int) *CertifyScorecardUpdateOne {
	if i != nil {
		csuo.SetSourceID(*i)
	}
	return csuo
}

// SetScorecardID sets the "scorecard_id" field.
func (csuo *CertifyScorecardUpdateOne) SetScorecardID(i int) *CertifyScorecardUpdateOne {
	csuo.mutation.SetScorecardID(i)
	return csuo
}

// SetNillableScorecardID sets the "scorecard_id" field if the given value is not nil.
func (csuo *CertifyScorecardUpdateOne) SetNillableScorecardID(i *int) *CertifyScorecardUpdateOne {
	if i != nil {
		csuo.SetScorecardID(*i)
	}
	return csuo
}

// SetScorecard sets the "scorecard" edge to the Scorecard entity.
func (csuo *CertifyScorecardUpdateOne) SetScorecard(s *Scorecard) *CertifyScorecardUpdateOne {
	return csuo.SetScorecardID(s.ID)
}

// SetSource sets the "source" edge to the SourceName entity.
func (csuo *CertifyScorecardUpdateOne) SetSource(s *SourceName) *CertifyScorecardUpdateOne {
	return csuo.SetSourceID(s.ID)
}

// Mutation returns the CertifyScorecardMutation object of the builder.
func (csuo *CertifyScorecardUpdateOne) Mutation() *CertifyScorecardMutation {
	return csuo.mutation
}

// ClearScorecard clears the "scorecard" edge to the Scorecard entity.
func (csuo *CertifyScorecardUpdateOne) ClearScorecard() *CertifyScorecardUpdateOne {
	csuo.mutation.ClearScorecard()
	return csuo
}

// ClearSource clears the "source" edge to the SourceName entity.
func (csuo *CertifyScorecardUpdateOne) ClearSource() *CertifyScorecardUpdateOne {
	csuo.mutation.ClearSource()
	return csuo
}

// Where appends a list predicates to the CertifyScorecardUpdate builder.
func (csuo *CertifyScorecardUpdateOne) Where(ps ...predicate.CertifyScorecard) *CertifyScorecardUpdateOne {
	csuo.mutation.Where(ps...)
	return csuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (csuo *CertifyScorecardUpdateOne) Select(field string, fields ...string) *CertifyScorecardUpdateOne {
	csuo.fields = append([]string{field}, fields...)
	return csuo
}

// Save executes the query and returns the updated CertifyScorecard entity.
func (csuo *CertifyScorecardUpdateOne) Save(ctx context.Context) (*CertifyScorecard, error) {
	return withHooks(ctx, csuo.sqlSave, csuo.mutation, csuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (csuo *CertifyScorecardUpdateOne) SaveX(ctx context.Context) *CertifyScorecard {
	node, err := csuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (csuo *CertifyScorecardUpdateOne) Exec(ctx context.Context) error {
	_, err := csuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (csuo *CertifyScorecardUpdateOne) ExecX(ctx context.Context) {
	if err := csuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (csuo *CertifyScorecardUpdateOne) check() error {
	if _, ok := csuo.mutation.ScorecardID(); csuo.mutation.ScorecardCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "CertifyScorecard.scorecard"`)
	}
	if _, ok := csuo.mutation.SourceID(); csuo.mutation.SourceCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "CertifyScorecard.source"`)
	}
	return nil
}

func (csuo *CertifyScorecardUpdateOne) sqlSave(ctx context.Context) (_node *CertifyScorecard, err error) {
	if err := csuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(certifyscorecard.Table, certifyscorecard.Columns, sqlgraph.NewFieldSpec(certifyscorecard.FieldID, field.TypeInt))
	id, ok := csuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "CertifyScorecard.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := csuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, certifyscorecard.FieldID)
		for _, f := range fields {
			if !certifyscorecard.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != certifyscorecard.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := csuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if csuo.mutation.ScorecardCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   certifyscorecard.ScorecardTable,
			Columns: []string{certifyscorecard.ScorecardColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(scorecard.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := csuo.mutation.ScorecardIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   certifyscorecard.ScorecardTable,
			Columns: []string{certifyscorecard.ScorecardColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(scorecard.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if csuo.mutation.SourceCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyscorecard.SourceTable,
			Columns: []string{certifyscorecard.SourceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(sourcename.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := csuo.mutation.SourceIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyscorecard.SourceTable,
			Columns: []string{certifyscorecard.SourceColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(sourcename.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &CertifyScorecard{config: csuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, csuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{certifyscorecard.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	csuo.mutation.done = true
	return _node, nil
}
