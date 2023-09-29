// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
)

// CertifyVexUpdate is the builder for updating CertifyVex entities.
type CertifyVexUpdate struct {
	config
	hooks    []Hook
	mutation *CertifyVexMutation
}

// Where appends a list predicates to the CertifyVexUpdate builder.
func (cvu *CertifyVexUpdate) Where(ps ...predicate.CertifyVex) *CertifyVexUpdate {
	cvu.mutation.Where(ps...)
	return cvu
}

// SetPackageID sets the "package_id" field.
func (cvu *CertifyVexUpdate) SetPackageID(i int) *CertifyVexUpdate {
	cvu.mutation.SetPackageID(i)
	return cvu
}

// SetNillablePackageID sets the "package_id" field if the given value is not nil.
func (cvu *CertifyVexUpdate) SetNillablePackageID(i *int) *CertifyVexUpdate {
	if i != nil {
		cvu.SetPackageID(*i)
	}
	return cvu
}

// ClearPackageID clears the value of the "package_id" field.
func (cvu *CertifyVexUpdate) ClearPackageID() *CertifyVexUpdate {
	cvu.mutation.ClearPackageID()
	return cvu
}

// SetArtifactID sets the "artifact_id" field.
func (cvu *CertifyVexUpdate) SetArtifactID(i int) *CertifyVexUpdate {
	cvu.mutation.SetArtifactID(i)
	return cvu
}

// SetNillableArtifactID sets the "artifact_id" field if the given value is not nil.
func (cvu *CertifyVexUpdate) SetNillableArtifactID(i *int) *CertifyVexUpdate {
	if i != nil {
		cvu.SetArtifactID(*i)
	}
	return cvu
}

// ClearArtifactID clears the value of the "artifact_id" field.
func (cvu *CertifyVexUpdate) ClearArtifactID() *CertifyVexUpdate {
	cvu.mutation.ClearArtifactID()
	return cvu
}

// SetVulnerabilityID sets the "vulnerability_id" field.
func (cvu *CertifyVexUpdate) SetVulnerabilityID(i int) *CertifyVexUpdate {
	cvu.mutation.SetVulnerabilityID(i)
	return cvu
}

// SetKnownSince sets the "known_since" field.
func (cvu *CertifyVexUpdate) SetKnownSince(t time.Time) *CertifyVexUpdate {
	cvu.mutation.SetKnownSince(t)
	return cvu
}

// SetStatus sets the "status" field.
func (cvu *CertifyVexUpdate) SetStatus(s string) *CertifyVexUpdate {
	cvu.mutation.SetStatus(s)
	return cvu
}

// SetStatement sets the "statement" field.
func (cvu *CertifyVexUpdate) SetStatement(s string) *CertifyVexUpdate {
	cvu.mutation.SetStatement(s)
	return cvu
}

// SetStatusNotes sets the "status_notes" field.
func (cvu *CertifyVexUpdate) SetStatusNotes(s string) *CertifyVexUpdate {
	cvu.mutation.SetStatusNotes(s)
	return cvu
}

// SetJustification sets the "justification" field.
func (cvu *CertifyVexUpdate) SetJustification(s string) *CertifyVexUpdate {
	cvu.mutation.SetJustification(s)
	return cvu
}

// SetOrigin sets the "origin" field.
func (cvu *CertifyVexUpdate) SetOrigin(s string) *CertifyVexUpdate {
	cvu.mutation.SetOrigin(s)
	return cvu
}

// SetCollector sets the "collector" field.
func (cvu *CertifyVexUpdate) SetCollector(s string) *CertifyVexUpdate {
	cvu.mutation.SetCollector(s)
	return cvu
}

// SetPackage sets the "package" edge to the PackageVersion entity.
func (cvu *CertifyVexUpdate) SetPackage(p *PackageVersion) *CertifyVexUpdate {
	return cvu.SetPackageID(p.ID)
}

// SetArtifact sets the "artifact" edge to the Artifact entity.
func (cvu *CertifyVexUpdate) SetArtifact(a *Artifact) *CertifyVexUpdate {
	return cvu.SetArtifactID(a.ID)
}

// SetVulnerability sets the "vulnerability" edge to the VulnerabilityID entity.
func (cvu *CertifyVexUpdate) SetVulnerability(v *VulnerabilityID) *CertifyVexUpdate {
	return cvu.SetVulnerabilityID(v.ID)
}

// Mutation returns the CertifyVexMutation object of the builder.
func (cvu *CertifyVexUpdate) Mutation() *CertifyVexMutation {
	return cvu.mutation
}

// ClearPackage clears the "package" edge to the PackageVersion entity.
func (cvu *CertifyVexUpdate) ClearPackage() *CertifyVexUpdate {
	cvu.mutation.ClearPackage()
	return cvu
}

// ClearArtifact clears the "artifact" edge to the Artifact entity.
func (cvu *CertifyVexUpdate) ClearArtifact() *CertifyVexUpdate {
	cvu.mutation.ClearArtifact()
	return cvu
}

// ClearVulnerability clears the "vulnerability" edge to the VulnerabilityID entity.
func (cvu *CertifyVexUpdate) ClearVulnerability() *CertifyVexUpdate {
	cvu.mutation.ClearVulnerability()
	return cvu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (cvu *CertifyVexUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, cvu.sqlSave, cvu.mutation, cvu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (cvu *CertifyVexUpdate) SaveX(ctx context.Context) int {
	affected, err := cvu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (cvu *CertifyVexUpdate) Exec(ctx context.Context) error {
	_, err := cvu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (cvu *CertifyVexUpdate) ExecX(ctx context.Context) {
	if err := cvu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (cvu *CertifyVexUpdate) check() error {
	if _, ok := cvu.mutation.VulnerabilityID(); cvu.mutation.VulnerabilityCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "CertifyVex.vulnerability"`)
	}
	return nil
}

func (cvu *CertifyVexUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := cvu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(certifyvex.Table, certifyvex.Columns, sqlgraph.NewFieldSpec(certifyvex.FieldID, field.TypeInt))
	if ps := cvu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := cvu.mutation.KnownSince(); ok {
		_spec.SetField(certifyvex.FieldKnownSince, field.TypeTime, value)
	}
	if value, ok := cvu.mutation.Status(); ok {
		_spec.SetField(certifyvex.FieldStatus, field.TypeString, value)
	}
	if value, ok := cvu.mutation.Statement(); ok {
		_spec.SetField(certifyvex.FieldStatement, field.TypeString, value)
	}
	if value, ok := cvu.mutation.StatusNotes(); ok {
		_spec.SetField(certifyvex.FieldStatusNotes, field.TypeString, value)
	}
	if value, ok := cvu.mutation.Justification(); ok {
		_spec.SetField(certifyvex.FieldJustification, field.TypeString, value)
	}
	if value, ok := cvu.mutation.Origin(); ok {
		_spec.SetField(certifyvex.FieldOrigin, field.TypeString, value)
	}
	if value, ok := cvu.mutation.Collector(); ok {
		_spec.SetField(certifyvex.FieldCollector, field.TypeString, value)
	}
	if cvu.mutation.PackageCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyvex.PackageTable,
			Columns: []string{certifyvex.PackageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := cvu.mutation.PackageIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyvex.PackageTable,
			Columns: []string{certifyvex.PackageColumn},
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
	if cvu.mutation.ArtifactCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyvex.ArtifactTable,
			Columns: []string{certifyvex.ArtifactColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := cvu.mutation.ArtifactIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyvex.ArtifactTable,
			Columns: []string{certifyvex.ArtifactColumn},
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
	if cvu.mutation.VulnerabilityCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyvex.VulnerabilityTable,
			Columns: []string{certifyvex.VulnerabilityColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(vulnerabilityid.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := cvu.mutation.VulnerabilityIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyvex.VulnerabilityTable,
			Columns: []string{certifyvex.VulnerabilityColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(vulnerabilityid.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, cvu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{certifyvex.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	cvu.mutation.done = true
	return n, nil
}

// CertifyVexUpdateOne is the builder for updating a single CertifyVex entity.
type CertifyVexUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *CertifyVexMutation
}

// SetPackageID sets the "package_id" field.
func (cvuo *CertifyVexUpdateOne) SetPackageID(i int) *CertifyVexUpdateOne {
	cvuo.mutation.SetPackageID(i)
	return cvuo
}

// SetNillablePackageID sets the "package_id" field if the given value is not nil.
func (cvuo *CertifyVexUpdateOne) SetNillablePackageID(i *int) *CertifyVexUpdateOne {
	if i != nil {
		cvuo.SetPackageID(*i)
	}
	return cvuo
}

// ClearPackageID clears the value of the "package_id" field.
func (cvuo *CertifyVexUpdateOne) ClearPackageID() *CertifyVexUpdateOne {
	cvuo.mutation.ClearPackageID()
	return cvuo
}

// SetArtifactID sets the "artifact_id" field.
func (cvuo *CertifyVexUpdateOne) SetArtifactID(i int) *CertifyVexUpdateOne {
	cvuo.mutation.SetArtifactID(i)
	return cvuo
}

// SetNillableArtifactID sets the "artifact_id" field if the given value is not nil.
func (cvuo *CertifyVexUpdateOne) SetNillableArtifactID(i *int) *CertifyVexUpdateOne {
	if i != nil {
		cvuo.SetArtifactID(*i)
	}
	return cvuo
}

// ClearArtifactID clears the value of the "artifact_id" field.
func (cvuo *CertifyVexUpdateOne) ClearArtifactID() *CertifyVexUpdateOne {
	cvuo.mutation.ClearArtifactID()
	return cvuo
}

// SetVulnerabilityID sets the "vulnerability_id" field.
func (cvuo *CertifyVexUpdateOne) SetVulnerabilityID(i int) *CertifyVexUpdateOne {
	cvuo.mutation.SetVulnerabilityID(i)
	return cvuo
}

// SetKnownSince sets the "known_since" field.
func (cvuo *CertifyVexUpdateOne) SetKnownSince(t time.Time) *CertifyVexUpdateOne {
	cvuo.mutation.SetKnownSince(t)
	return cvuo
}

// SetStatus sets the "status" field.
func (cvuo *CertifyVexUpdateOne) SetStatus(s string) *CertifyVexUpdateOne {
	cvuo.mutation.SetStatus(s)
	return cvuo
}

// SetStatement sets the "statement" field.
func (cvuo *CertifyVexUpdateOne) SetStatement(s string) *CertifyVexUpdateOne {
	cvuo.mutation.SetStatement(s)
	return cvuo
}

// SetStatusNotes sets the "status_notes" field.
func (cvuo *CertifyVexUpdateOne) SetStatusNotes(s string) *CertifyVexUpdateOne {
	cvuo.mutation.SetStatusNotes(s)
	return cvuo
}

// SetJustification sets the "justification" field.
func (cvuo *CertifyVexUpdateOne) SetJustification(s string) *CertifyVexUpdateOne {
	cvuo.mutation.SetJustification(s)
	return cvuo
}

// SetOrigin sets the "origin" field.
func (cvuo *CertifyVexUpdateOne) SetOrigin(s string) *CertifyVexUpdateOne {
	cvuo.mutation.SetOrigin(s)
	return cvuo
}

// SetCollector sets the "collector" field.
func (cvuo *CertifyVexUpdateOne) SetCollector(s string) *CertifyVexUpdateOne {
	cvuo.mutation.SetCollector(s)
	return cvuo
}

// SetPackage sets the "package" edge to the PackageVersion entity.
func (cvuo *CertifyVexUpdateOne) SetPackage(p *PackageVersion) *CertifyVexUpdateOne {
	return cvuo.SetPackageID(p.ID)
}

// SetArtifact sets the "artifact" edge to the Artifact entity.
func (cvuo *CertifyVexUpdateOne) SetArtifact(a *Artifact) *CertifyVexUpdateOne {
	return cvuo.SetArtifactID(a.ID)
}

// SetVulnerability sets the "vulnerability" edge to the VulnerabilityID entity.
func (cvuo *CertifyVexUpdateOne) SetVulnerability(v *VulnerabilityID) *CertifyVexUpdateOne {
	return cvuo.SetVulnerabilityID(v.ID)
}

// Mutation returns the CertifyVexMutation object of the builder.
func (cvuo *CertifyVexUpdateOne) Mutation() *CertifyVexMutation {
	return cvuo.mutation
}

// ClearPackage clears the "package" edge to the PackageVersion entity.
func (cvuo *CertifyVexUpdateOne) ClearPackage() *CertifyVexUpdateOne {
	cvuo.mutation.ClearPackage()
	return cvuo
}

// ClearArtifact clears the "artifact" edge to the Artifact entity.
func (cvuo *CertifyVexUpdateOne) ClearArtifact() *CertifyVexUpdateOne {
	cvuo.mutation.ClearArtifact()
	return cvuo
}

// ClearVulnerability clears the "vulnerability" edge to the VulnerabilityID entity.
func (cvuo *CertifyVexUpdateOne) ClearVulnerability() *CertifyVexUpdateOne {
	cvuo.mutation.ClearVulnerability()
	return cvuo
}

// Where appends a list predicates to the CertifyVexUpdate builder.
func (cvuo *CertifyVexUpdateOne) Where(ps ...predicate.CertifyVex) *CertifyVexUpdateOne {
	cvuo.mutation.Where(ps...)
	return cvuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (cvuo *CertifyVexUpdateOne) Select(field string, fields ...string) *CertifyVexUpdateOne {
	cvuo.fields = append([]string{field}, fields...)
	return cvuo
}

// Save executes the query and returns the updated CertifyVex entity.
func (cvuo *CertifyVexUpdateOne) Save(ctx context.Context) (*CertifyVex, error) {
	return withHooks(ctx, cvuo.sqlSave, cvuo.mutation, cvuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (cvuo *CertifyVexUpdateOne) SaveX(ctx context.Context) *CertifyVex {
	node, err := cvuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (cvuo *CertifyVexUpdateOne) Exec(ctx context.Context) error {
	_, err := cvuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (cvuo *CertifyVexUpdateOne) ExecX(ctx context.Context) {
	if err := cvuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (cvuo *CertifyVexUpdateOne) check() error {
	if _, ok := cvuo.mutation.VulnerabilityID(); cvuo.mutation.VulnerabilityCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "CertifyVex.vulnerability"`)
	}
	return nil
}

func (cvuo *CertifyVexUpdateOne) sqlSave(ctx context.Context) (_node *CertifyVex, err error) {
	if err := cvuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(certifyvex.Table, certifyvex.Columns, sqlgraph.NewFieldSpec(certifyvex.FieldID, field.TypeInt))
	id, ok := cvuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "CertifyVex.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := cvuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, certifyvex.FieldID)
		for _, f := range fields {
			if !certifyvex.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != certifyvex.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := cvuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := cvuo.mutation.KnownSince(); ok {
		_spec.SetField(certifyvex.FieldKnownSince, field.TypeTime, value)
	}
	if value, ok := cvuo.mutation.Status(); ok {
		_spec.SetField(certifyvex.FieldStatus, field.TypeString, value)
	}
	if value, ok := cvuo.mutation.Statement(); ok {
		_spec.SetField(certifyvex.FieldStatement, field.TypeString, value)
	}
	if value, ok := cvuo.mutation.StatusNotes(); ok {
		_spec.SetField(certifyvex.FieldStatusNotes, field.TypeString, value)
	}
	if value, ok := cvuo.mutation.Justification(); ok {
		_spec.SetField(certifyvex.FieldJustification, field.TypeString, value)
	}
	if value, ok := cvuo.mutation.Origin(); ok {
		_spec.SetField(certifyvex.FieldOrigin, field.TypeString, value)
	}
	if value, ok := cvuo.mutation.Collector(); ok {
		_spec.SetField(certifyvex.FieldCollector, field.TypeString, value)
	}
	if cvuo.mutation.PackageCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyvex.PackageTable,
			Columns: []string{certifyvex.PackageColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(packageversion.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := cvuo.mutation.PackageIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyvex.PackageTable,
			Columns: []string{certifyvex.PackageColumn},
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
	if cvuo.mutation.ArtifactCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyvex.ArtifactTable,
			Columns: []string{certifyvex.ArtifactColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := cvuo.mutation.ArtifactIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyvex.ArtifactTable,
			Columns: []string{certifyvex.ArtifactColumn},
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
	if cvuo.mutation.VulnerabilityCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyvex.VulnerabilityTable,
			Columns: []string{certifyvex.VulnerabilityColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(vulnerabilityid.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := cvuo.mutation.VulnerabilityIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   certifyvex.VulnerabilityTable,
			Columns: []string{certifyvex.VulnerabilityColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(vulnerabilityid.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &CertifyVex{config: cvuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, cvuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{certifyvex.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	cvuo.mutation.done = true
	return _node, nil
}
