// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/builder"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/slsaattestation"
)

// SLSAAttestationQuery is the builder for querying SLSAAttestation entities.
type SLSAAttestationQuery struct {
	config
	ctx           *QueryContext
	order         []slsaattestation.OrderOption
	inters        []Interceptor
	predicates    []predicate.SLSAAttestation
	withBuiltFrom *ArtifactQuery
	withBuiltBy   *BuilderQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the SLSAAttestationQuery builder.
func (saq *SLSAAttestationQuery) Where(ps ...predicate.SLSAAttestation) *SLSAAttestationQuery {
	saq.predicates = append(saq.predicates, ps...)
	return saq
}

// Limit the number of records to be returned by this query.
func (saq *SLSAAttestationQuery) Limit(limit int) *SLSAAttestationQuery {
	saq.ctx.Limit = &limit
	return saq
}

// Offset to start from.
func (saq *SLSAAttestationQuery) Offset(offset int) *SLSAAttestationQuery {
	saq.ctx.Offset = &offset
	return saq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (saq *SLSAAttestationQuery) Unique(unique bool) *SLSAAttestationQuery {
	saq.ctx.Unique = &unique
	return saq
}

// Order specifies how the records should be ordered.
func (saq *SLSAAttestationQuery) Order(o ...slsaattestation.OrderOption) *SLSAAttestationQuery {
	saq.order = append(saq.order, o...)
	return saq
}

// QueryBuiltFrom chains the current query on the "built_from" edge.
func (saq *SLSAAttestationQuery) QueryBuiltFrom() *ArtifactQuery {
	query := (&ArtifactClient{config: saq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := saq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := saq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(slsaattestation.Table, slsaattestation.FieldID, selector),
			sqlgraph.To(artifact.Table, artifact.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, slsaattestation.BuiltFromTable, slsaattestation.BuiltFromColumn),
		)
		fromU = sqlgraph.SetNeighbors(saq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryBuiltBy chains the current query on the "built_by" edge.
func (saq *SLSAAttestationQuery) QueryBuiltBy() *BuilderQuery {
	query := (&BuilderClient{config: saq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := saq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := saq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(slsaattestation.Table, slsaattestation.FieldID, selector),
			sqlgraph.To(builder.Table, builder.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, slsaattestation.BuiltByTable, slsaattestation.BuiltByColumn),
		)
		fromU = sqlgraph.SetNeighbors(saq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first SLSAAttestation entity from the query.
// Returns a *NotFoundError when no SLSAAttestation was found.
func (saq *SLSAAttestationQuery) First(ctx context.Context) (*SLSAAttestation, error) {
	nodes, err := saq.Limit(1).All(setContextOp(ctx, saq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{slsaattestation.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (saq *SLSAAttestationQuery) FirstX(ctx context.Context) *SLSAAttestation {
	node, err := saq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first SLSAAttestation ID from the query.
// Returns a *NotFoundError when no SLSAAttestation ID was found.
func (saq *SLSAAttestationQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = saq.Limit(1).IDs(setContextOp(ctx, saq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{slsaattestation.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (saq *SLSAAttestationQuery) FirstIDX(ctx context.Context) int {
	id, err := saq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single SLSAAttestation entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one SLSAAttestation entity is found.
// Returns a *NotFoundError when no SLSAAttestation entities are found.
func (saq *SLSAAttestationQuery) Only(ctx context.Context) (*SLSAAttestation, error) {
	nodes, err := saq.Limit(2).All(setContextOp(ctx, saq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{slsaattestation.Label}
	default:
		return nil, &NotSingularError{slsaattestation.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (saq *SLSAAttestationQuery) OnlyX(ctx context.Context) *SLSAAttestation {
	node, err := saq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only SLSAAttestation ID in the query.
// Returns a *NotSingularError when more than one SLSAAttestation ID is found.
// Returns a *NotFoundError when no entities are found.
func (saq *SLSAAttestationQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = saq.Limit(2).IDs(setContextOp(ctx, saq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{slsaattestation.Label}
	default:
		err = &NotSingularError{slsaattestation.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (saq *SLSAAttestationQuery) OnlyIDX(ctx context.Context) int {
	id, err := saq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of SLSAAttestations.
func (saq *SLSAAttestationQuery) All(ctx context.Context) ([]*SLSAAttestation, error) {
	ctx = setContextOp(ctx, saq.ctx, "All")
	if err := saq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*SLSAAttestation, *SLSAAttestationQuery]()
	return withInterceptors[[]*SLSAAttestation](ctx, saq, qr, saq.inters)
}

// AllX is like All, but panics if an error occurs.
func (saq *SLSAAttestationQuery) AllX(ctx context.Context) []*SLSAAttestation {
	nodes, err := saq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of SLSAAttestation IDs.
func (saq *SLSAAttestationQuery) IDs(ctx context.Context) (ids []int, err error) {
	if saq.ctx.Unique == nil && saq.path != nil {
		saq.Unique(true)
	}
	ctx = setContextOp(ctx, saq.ctx, "IDs")
	if err = saq.Select(slsaattestation.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (saq *SLSAAttestationQuery) IDsX(ctx context.Context) []int {
	ids, err := saq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (saq *SLSAAttestationQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, saq.ctx, "Count")
	if err := saq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, saq, querierCount[*SLSAAttestationQuery](), saq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (saq *SLSAAttestationQuery) CountX(ctx context.Context) int {
	count, err := saq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (saq *SLSAAttestationQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, saq.ctx, "Exist")
	switch _, err := saq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (saq *SLSAAttestationQuery) ExistX(ctx context.Context) bool {
	exist, err := saq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the SLSAAttestationQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (saq *SLSAAttestationQuery) Clone() *SLSAAttestationQuery {
	if saq == nil {
		return nil
	}
	return &SLSAAttestationQuery{
		config:        saq.config,
		ctx:           saq.ctx.Clone(),
		order:         append([]slsaattestation.OrderOption{}, saq.order...),
		inters:        append([]Interceptor{}, saq.inters...),
		predicates:    append([]predicate.SLSAAttestation{}, saq.predicates...),
		withBuiltFrom: saq.withBuiltFrom.Clone(),
		withBuiltBy:   saq.withBuiltBy.Clone(),
		// clone intermediate query.
		sql:  saq.sql.Clone(),
		path: saq.path,
	}
}

// WithBuiltFrom tells the query-builder to eager-load the nodes that are connected to
// the "built_from" edge. The optional arguments are used to configure the query builder of the edge.
func (saq *SLSAAttestationQuery) WithBuiltFrom(opts ...func(*ArtifactQuery)) *SLSAAttestationQuery {
	query := (&ArtifactClient{config: saq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	saq.withBuiltFrom = query
	return saq
}

// WithBuiltBy tells the query-builder to eager-load the nodes that are connected to
// the "built_by" edge. The optional arguments are used to configure the query builder of the edge.
func (saq *SLSAAttestationQuery) WithBuiltBy(opts ...func(*BuilderQuery)) *SLSAAttestationQuery {
	query := (&BuilderClient{config: saq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	saq.withBuiltBy = query
	return saq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		BuildType string `json:"build_type,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.SLSAAttestation.Query().
//		GroupBy(slsaattestation.FieldBuildType).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (saq *SLSAAttestationQuery) GroupBy(field string, fields ...string) *SLSAAttestationGroupBy {
	saq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &SLSAAttestationGroupBy{build: saq}
	grbuild.flds = &saq.ctx.Fields
	grbuild.label = slsaattestation.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		BuildType string `json:"build_type,omitempty"`
//	}
//
//	client.SLSAAttestation.Query().
//		Select(slsaattestation.FieldBuildType).
//		Scan(ctx, &v)
func (saq *SLSAAttestationQuery) Select(fields ...string) *SLSAAttestationSelect {
	saq.ctx.Fields = append(saq.ctx.Fields, fields...)
	sbuild := &SLSAAttestationSelect{SLSAAttestationQuery: saq}
	sbuild.label = slsaattestation.Label
	sbuild.flds, sbuild.scan = &saq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a SLSAAttestationSelect configured with the given aggregations.
func (saq *SLSAAttestationQuery) Aggregate(fns ...AggregateFunc) *SLSAAttestationSelect {
	return saq.Select().Aggregate(fns...)
}

func (saq *SLSAAttestationQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range saq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, saq); err != nil {
				return err
			}
		}
	}
	for _, f := range saq.ctx.Fields {
		if !slsaattestation.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if saq.path != nil {
		prev, err := saq.path(ctx)
		if err != nil {
			return err
		}
		saq.sql = prev
	}
	return nil
}

func (saq *SLSAAttestationQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*SLSAAttestation, error) {
	var (
		nodes       = []*SLSAAttestation{}
		_spec       = saq.querySpec()
		loadedTypes = [2]bool{
			saq.withBuiltFrom != nil,
			saq.withBuiltBy != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*SLSAAttestation).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &SLSAAttestation{config: saq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, saq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := saq.withBuiltFrom; query != nil {
		if err := saq.loadBuiltFrom(ctx, query, nodes,
			func(n *SLSAAttestation) { n.Edges.BuiltFrom = []*Artifact{} },
			func(n *SLSAAttestation, e *Artifact) { n.Edges.BuiltFrom = append(n.Edges.BuiltFrom, e) }); err != nil {
			return nil, err
		}
	}
	if query := saq.withBuiltBy; query != nil {
		if err := saq.loadBuiltBy(ctx, query, nodes,
			func(n *SLSAAttestation) { n.Edges.BuiltBy = []*Builder{} },
			func(n *SLSAAttestation, e *Builder) { n.Edges.BuiltBy = append(n.Edges.BuiltBy, e) }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (saq *SLSAAttestationQuery) loadBuiltFrom(ctx context.Context, query *ArtifactQuery, nodes []*SLSAAttestation, init func(*SLSAAttestation), assign func(*SLSAAttestation, *Artifact)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[int]*SLSAAttestation)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.Artifact(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(slsaattestation.BuiltFromColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.slsa_attestation_built_from
		if fk == nil {
			return fmt.Errorf(`foreign-key "slsa_attestation_built_from" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "slsa_attestation_built_from" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (saq *SLSAAttestationQuery) loadBuiltBy(ctx context.Context, query *BuilderQuery, nodes []*SLSAAttestation, init func(*SLSAAttestation), assign func(*SLSAAttestation, *Builder)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[int]*SLSAAttestation)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.Builder(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(slsaattestation.BuiltByColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.slsa_attestation_built_by
		if fk == nil {
			return fmt.Errorf(`foreign-key "slsa_attestation_built_by" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "slsa_attestation_built_by" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}

func (saq *SLSAAttestationQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := saq.querySpec()
	_spec.Node.Columns = saq.ctx.Fields
	if len(saq.ctx.Fields) > 0 {
		_spec.Unique = saq.ctx.Unique != nil && *saq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, saq.driver, _spec)
}

func (saq *SLSAAttestationQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(slsaattestation.Table, slsaattestation.Columns, sqlgraph.NewFieldSpec(slsaattestation.FieldID, field.TypeInt))
	_spec.From = saq.sql
	if unique := saq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if saq.path != nil {
		_spec.Unique = true
	}
	if fields := saq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, slsaattestation.FieldID)
		for i := range fields {
			if fields[i] != slsaattestation.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := saq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := saq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := saq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := saq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (saq *SLSAAttestationQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(saq.driver.Dialect())
	t1 := builder.Table(slsaattestation.Table)
	columns := saq.ctx.Fields
	if len(columns) == 0 {
		columns = slsaattestation.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if saq.sql != nil {
		selector = saq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if saq.ctx.Unique != nil && *saq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range saq.predicates {
		p(selector)
	}
	for _, p := range saq.order {
		p(selector)
	}
	if offset := saq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := saq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// SLSAAttestationGroupBy is the group-by builder for SLSAAttestation entities.
type SLSAAttestationGroupBy struct {
	selector
	build *SLSAAttestationQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (sagb *SLSAAttestationGroupBy) Aggregate(fns ...AggregateFunc) *SLSAAttestationGroupBy {
	sagb.fns = append(sagb.fns, fns...)
	return sagb
}

// Scan applies the selector query and scans the result into the given value.
func (sagb *SLSAAttestationGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, sagb.build.ctx, "GroupBy")
	if err := sagb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*SLSAAttestationQuery, *SLSAAttestationGroupBy](ctx, sagb.build, sagb, sagb.build.inters, v)
}

func (sagb *SLSAAttestationGroupBy) sqlScan(ctx context.Context, root *SLSAAttestationQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(sagb.fns))
	for _, fn := range sagb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*sagb.flds)+len(sagb.fns))
		for _, f := range *sagb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*sagb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := sagb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// SLSAAttestationSelect is the builder for selecting fields of SLSAAttestation entities.
type SLSAAttestationSelect struct {
	*SLSAAttestationQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (sas *SLSAAttestationSelect) Aggregate(fns ...AggregateFunc) *SLSAAttestationSelect {
	sas.fns = append(sas.fns, fns...)
	return sas
}

// Scan applies the selector query and scans the result into the given value.
func (sas *SLSAAttestationSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, sas.ctx, "Select")
	if err := sas.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*SLSAAttestationQuery, *SLSAAttestationSelect](ctx, sas.SLSAAttestationQuery, sas, sas.inters, v)
}

func (sas *SLSAAttestationSelect) sqlScan(ctx context.Context, root *SLSAAttestationQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(sas.fns))
	for _, fn := range sas.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*sas.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := sas.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
