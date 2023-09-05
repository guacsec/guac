// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvuln"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
)

// CertifyVulnQuery is the builder for querying CertifyVuln entities.
type CertifyVulnQuery struct {
	config
	ctx               *QueryContext
	order             []certifyvuln.OrderOption
	inters            []Interceptor
	predicates        []predicate.CertifyVuln
	withVulnerability *VulnerabilityIDQuery
	withPackage       *PackageVersionQuery
	modifiers         []func(*sql.Selector)
	loadTotal         []func(context.Context, []*CertifyVuln) error
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the CertifyVulnQuery builder.
func (cvq *CertifyVulnQuery) Where(ps ...predicate.CertifyVuln) *CertifyVulnQuery {
	cvq.predicates = append(cvq.predicates, ps...)
	return cvq
}

// Limit the number of records to be returned by this query.
func (cvq *CertifyVulnQuery) Limit(limit int) *CertifyVulnQuery {
	cvq.ctx.Limit = &limit
	return cvq
}

// Offset to start from.
func (cvq *CertifyVulnQuery) Offset(offset int) *CertifyVulnQuery {
	cvq.ctx.Offset = &offset
	return cvq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (cvq *CertifyVulnQuery) Unique(unique bool) *CertifyVulnQuery {
	cvq.ctx.Unique = &unique
	return cvq
}

// Order specifies how the records should be ordered.
func (cvq *CertifyVulnQuery) Order(o ...certifyvuln.OrderOption) *CertifyVulnQuery {
	cvq.order = append(cvq.order, o...)
	return cvq
}

// QueryVulnerability chains the current query on the "vulnerability" edge.
func (cvq *CertifyVulnQuery) QueryVulnerability() *VulnerabilityIDQuery {
	query := (&VulnerabilityIDClient{config: cvq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := cvq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := cvq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(certifyvuln.Table, certifyvuln.FieldID, selector),
			sqlgraph.To(vulnerabilityid.Table, vulnerabilityid.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, certifyvuln.VulnerabilityTable, certifyvuln.VulnerabilityColumn),
		)
		fromU = sqlgraph.SetNeighbors(cvq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryPackage chains the current query on the "package" edge.
func (cvq *CertifyVulnQuery) QueryPackage() *PackageVersionQuery {
	query := (&PackageVersionClient{config: cvq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := cvq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := cvq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(certifyvuln.Table, certifyvuln.FieldID, selector),
			sqlgraph.To(packageversion.Table, packageversion.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, certifyvuln.PackageTable, certifyvuln.PackageColumn),
		)
		fromU = sqlgraph.SetNeighbors(cvq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first CertifyVuln entity from the query.
// Returns a *NotFoundError when no CertifyVuln was found.
func (cvq *CertifyVulnQuery) First(ctx context.Context) (*CertifyVuln, error) {
	nodes, err := cvq.Limit(1).All(setContextOp(ctx, cvq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{certifyvuln.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (cvq *CertifyVulnQuery) FirstX(ctx context.Context) *CertifyVuln {
	node, err := cvq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first CertifyVuln ID from the query.
// Returns a *NotFoundError when no CertifyVuln ID was found.
func (cvq *CertifyVulnQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = cvq.Limit(1).IDs(setContextOp(ctx, cvq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{certifyvuln.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (cvq *CertifyVulnQuery) FirstIDX(ctx context.Context) int {
	id, err := cvq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single CertifyVuln entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one CertifyVuln entity is found.
// Returns a *NotFoundError when no CertifyVuln entities are found.
func (cvq *CertifyVulnQuery) Only(ctx context.Context) (*CertifyVuln, error) {
	nodes, err := cvq.Limit(2).All(setContextOp(ctx, cvq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{certifyvuln.Label}
	default:
		return nil, &NotSingularError{certifyvuln.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (cvq *CertifyVulnQuery) OnlyX(ctx context.Context) *CertifyVuln {
	node, err := cvq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only CertifyVuln ID in the query.
// Returns a *NotSingularError when more than one CertifyVuln ID is found.
// Returns a *NotFoundError when no entities are found.
func (cvq *CertifyVulnQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = cvq.Limit(2).IDs(setContextOp(ctx, cvq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{certifyvuln.Label}
	default:
		err = &NotSingularError{certifyvuln.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (cvq *CertifyVulnQuery) OnlyIDX(ctx context.Context) int {
	id, err := cvq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of CertifyVulns.
func (cvq *CertifyVulnQuery) All(ctx context.Context) ([]*CertifyVuln, error) {
	ctx = setContextOp(ctx, cvq.ctx, "All")
	if err := cvq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*CertifyVuln, *CertifyVulnQuery]()
	return withInterceptors[[]*CertifyVuln](ctx, cvq, qr, cvq.inters)
}

// AllX is like All, but panics if an error occurs.
func (cvq *CertifyVulnQuery) AllX(ctx context.Context) []*CertifyVuln {
	nodes, err := cvq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of CertifyVuln IDs.
func (cvq *CertifyVulnQuery) IDs(ctx context.Context) (ids []int, err error) {
	if cvq.ctx.Unique == nil && cvq.path != nil {
		cvq.Unique(true)
	}
	ctx = setContextOp(ctx, cvq.ctx, "IDs")
	if err = cvq.Select(certifyvuln.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (cvq *CertifyVulnQuery) IDsX(ctx context.Context) []int {
	ids, err := cvq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (cvq *CertifyVulnQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, cvq.ctx, "Count")
	if err := cvq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, cvq, querierCount[*CertifyVulnQuery](), cvq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (cvq *CertifyVulnQuery) CountX(ctx context.Context) int {
	count, err := cvq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (cvq *CertifyVulnQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, cvq.ctx, "Exist")
	switch _, err := cvq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (cvq *CertifyVulnQuery) ExistX(ctx context.Context) bool {
	exist, err := cvq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the CertifyVulnQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (cvq *CertifyVulnQuery) Clone() *CertifyVulnQuery {
	if cvq == nil {
		return nil
	}
	return &CertifyVulnQuery{
		config:            cvq.config,
		ctx:               cvq.ctx.Clone(),
		order:             append([]certifyvuln.OrderOption{}, cvq.order...),
		inters:            append([]Interceptor{}, cvq.inters...),
		predicates:        append([]predicate.CertifyVuln{}, cvq.predicates...),
		withVulnerability: cvq.withVulnerability.Clone(),
		withPackage:       cvq.withPackage.Clone(),
		// clone intermediate query.
		sql:  cvq.sql.Clone(),
		path: cvq.path,
	}
}

// WithVulnerability tells the query-builder to eager-load the nodes that are connected to
// the "vulnerability" edge. The optional arguments are used to configure the query builder of the edge.
func (cvq *CertifyVulnQuery) WithVulnerability(opts ...func(*VulnerabilityIDQuery)) *CertifyVulnQuery {
	query := (&VulnerabilityIDClient{config: cvq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	cvq.withVulnerability = query
	return cvq
}

// WithPackage tells the query-builder to eager-load the nodes that are connected to
// the "package" edge. The optional arguments are used to configure the query builder of the edge.
func (cvq *CertifyVulnQuery) WithPackage(opts ...func(*PackageVersionQuery)) *CertifyVulnQuery {
	query := (&PackageVersionClient{config: cvq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	cvq.withPackage = query
	return cvq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		VulnerabilityID int `json:"vulnerability_id,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.CertifyVuln.Query().
//		GroupBy(certifyvuln.FieldVulnerabilityID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (cvq *CertifyVulnQuery) GroupBy(field string, fields ...string) *CertifyVulnGroupBy {
	cvq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &CertifyVulnGroupBy{build: cvq}
	grbuild.flds = &cvq.ctx.Fields
	grbuild.label = certifyvuln.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		VulnerabilityID int `json:"vulnerability_id,omitempty"`
//	}
//
//	client.CertifyVuln.Query().
//		Select(certifyvuln.FieldVulnerabilityID).
//		Scan(ctx, &v)
func (cvq *CertifyVulnQuery) Select(fields ...string) *CertifyVulnSelect {
	cvq.ctx.Fields = append(cvq.ctx.Fields, fields...)
	sbuild := &CertifyVulnSelect{CertifyVulnQuery: cvq}
	sbuild.label = certifyvuln.Label
	sbuild.flds, sbuild.scan = &cvq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a CertifyVulnSelect configured with the given aggregations.
func (cvq *CertifyVulnQuery) Aggregate(fns ...AggregateFunc) *CertifyVulnSelect {
	return cvq.Select().Aggregate(fns...)
}

func (cvq *CertifyVulnQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range cvq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, cvq); err != nil {
				return err
			}
		}
	}
	for _, f := range cvq.ctx.Fields {
		if !certifyvuln.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if cvq.path != nil {
		prev, err := cvq.path(ctx)
		if err != nil {
			return err
		}
		cvq.sql = prev
	}
	return nil
}

func (cvq *CertifyVulnQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*CertifyVuln, error) {
	var (
		nodes       = []*CertifyVuln{}
		_spec       = cvq.querySpec()
		loadedTypes = [2]bool{
			cvq.withVulnerability != nil,
			cvq.withPackage != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*CertifyVuln).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &CertifyVuln{config: cvq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(cvq.modifiers) > 0 {
		_spec.Modifiers = cvq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, cvq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := cvq.withVulnerability; query != nil {
		if err := cvq.loadVulnerability(ctx, query, nodes, nil,
			func(n *CertifyVuln, e *VulnerabilityID) { n.Edges.Vulnerability = e }); err != nil {
			return nil, err
		}
	}
	if query := cvq.withPackage; query != nil {
		if err := cvq.loadPackage(ctx, query, nodes, nil,
			func(n *CertifyVuln, e *PackageVersion) { n.Edges.Package = e }); err != nil {
			return nil, err
		}
	}
	for i := range cvq.loadTotal {
		if err := cvq.loadTotal[i](ctx, nodes); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (cvq *CertifyVulnQuery) loadVulnerability(ctx context.Context, query *VulnerabilityIDQuery, nodes []*CertifyVuln, init func(*CertifyVuln), assign func(*CertifyVuln, *VulnerabilityID)) error {
	ids := make([]int, 0, len(nodes))
	nodeids := make(map[int][]*CertifyVuln)
	for i := range nodes {
		fk := nodes[i].VulnerabilityID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(vulnerabilityid.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "vulnerability_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (cvq *CertifyVulnQuery) loadPackage(ctx context.Context, query *PackageVersionQuery, nodes []*CertifyVuln, init func(*CertifyVuln), assign func(*CertifyVuln, *PackageVersion)) error {
	ids := make([]int, 0, len(nodes))
	nodeids := make(map[int][]*CertifyVuln)
	for i := range nodes {
		fk := nodes[i].PackageID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(packageversion.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "package_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (cvq *CertifyVulnQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := cvq.querySpec()
	if len(cvq.modifiers) > 0 {
		_spec.Modifiers = cvq.modifiers
	}
	_spec.Node.Columns = cvq.ctx.Fields
	if len(cvq.ctx.Fields) > 0 {
		_spec.Unique = cvq.ctx.Unique != nil && *cvq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, cvq.driver, _spec)
}

func (cvq *CertifyVulnQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(certifyvuln.Table, certifyvuln.Columns, sqlgraph.NewFieldSpec(certifyvuln.FieldID, field.TypeInt))
	_spec.From = cvq.sql
	if unique := cvq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if cvq.path != nil {
		_spec.Unique = true
	}
	if fields := cvq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, certifyvuln.FieldID)
		for i := range fields {
			if fields[i] != certifyvuln.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
		if cvq.withVulnerability != nil {
			_spec.Node.AddColumnOnce(certifyvuln.FieldVulnerabilityID)
		}
		if cvq.withPackage != nil {
			_spec.Node.AddColumnOnce(certifyvuln.FieldPackageID)
		}
	}
	if ps := cvq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := cvq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := cvq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := cvq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (cvq *CertifyVulnQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(cvq.driver.Dialect())
	t1 := builder.Table(certifyvuln.Table)
	columns := cvq.ctx.Fields
	if len(columns) == 0 {
		columns = certifyvuln.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if cvq.sql != nil {
		selector = cvq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if cvq.ctx.Unique != nil && *cvq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range cvq.predicates {
		p(selector)
	}
	for _, p := range cvq.order {
		p(selector)
	}
	if offset := cvq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := cvq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// CertifyVulnGroupBy is the group-by builder for CertifyVuln entities.
type CertifyVulnGroupBy struct {
	selector
	build *CertifyVulnQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (cvgb *CertifyVulnGroupBy) Aggregate(fns ...AggregateFunc) *CertifyVulnGroupBy {
	cvgb.fns = append(cvgb.fns, fns...)
	return cvgb
}

// Scan applies the selector query and scans the result into the given value.
func (cvgb *CertifyVulnGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, cvgb.build.ctx, "GroupBy")
	if err := cvgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*CertifyVulnQuery, *CertifyVulnGroupBy](ctx, cvgb.build, cvgb, cvgb.build.inters, v)
}

func (cvgb *CertifyVulnGroupBy) sqlScan(ctx context.Context, root *CertifyVulnQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(cvgb.fns))
	for _, fn := range cvgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*cvgb.flds)+len(cvgb.fns))
		for _, f := range *cvgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*cvgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := cvgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// CertifyVulnSelect is the builder for selecting fields of CertifyVuln entities.
type CertifyVulnSelect struct {
	*CertifyVulnQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (cvs *CertifyVulnSelect) Aggregate(fns ...AggregateFunc) *CertifyVulnSelect {
	cvs.fns = append(cvs.fns, fns...)
	return cvs
}

// Scan applies the selector query and scans the result into the given value.
func (cvs *CertifyVulnSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, cvs.ctx, "Select")
	if err := cvs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*CertifyVulnQuery, *CertifyVulnSelect](ctx, cvs.CertifyVulnQuery, cvs, cvs.inters, v)
}

func (cvs *CertifyVulnSelect) sqlScan(ctx context.Context, root *CertifyVulnQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(cvs.fns))
	for _, fn := range cvs.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*cvs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := cvs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
