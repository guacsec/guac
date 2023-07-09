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
	"github.com/guacsec/guac/pkg/assembler/backends/ent/billofmaterials"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/hashequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/slsaattestation"
)

// ArtifactQuery is the builder for querying Artifact entities.
type ArtifactQuery struct {
	config
	ctx              *QueryContext
	order            []artifact.OrderOption
	inters           []Interceptor
	predicates       []predicate.Artifact
	withOccurrences  *OccurrenceQuery
	withSbom         *BillOfMaterialsQuery
	withAttestations *SLSAAttestationQuery
	withSame         *HashEqualQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the ArtifactQuery builder.
func (aq *ArtifactQuery) Where(ps ...predicate.Artifact) *ArtifactQuery {
	aq.predicates = append(aq.predicates, ps...)
	return aq
}

// Limit the number of records to be returned by this query.
func (aq *ArtifactQuery) Limit(limit int) *ArtifactQuery {
	aq.ctx.Limit = &limit
	return aq
}

// Offset to start from.
func (aq *ArtifactQuery) Offset(offset int) *ArtifactQuery {
	aq.ctx.Offset = &offset
	return aq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (aq *ArtifactQuery) Unique(unique bool) *ArtifactQuery {
	aq.ctx.Unique = &unique
	return aq
}

// Order specifies how the records should be ordered.
func (aq *ArtifactQuery) Order(o ...artifact.OrderOption) *ArtifactQuery {
	aq.order = append(aq.order, o...)
	return aq
}

// QueryOccurrences chains the current query on the "occurrences" edge.
func (aq *ArtifactQuery) QueryOccurrences() *OccurrenceQuery {
	query := (&OccurrenceClient{config: aq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := aq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := aq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(artifact.Table, artifact.FieldID, selector),
			sqlgraph.To(occurrence.Table, occurrence.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, artifact.OccurrencesTable, artifact.OccurrencesColumn),
		)
		fromU = sqlgraph.SetNeighbors(aq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QuerySbom chains the current query on the "sbom" edge.
func (aq *ArtifactQuery) QuerySbom() *BillOfMaterialsQuery {
	query := (&BillOfMaterialsClient{config: aq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := aq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := aq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(artifact.Table, artifact.FieldID, selector),
			sqlgraph.To(billofmaterials.Table, billofmaterials.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, artifact.SbomTable, artifact.SbomColumn),
		)
		fromU = sqlgraph.SetNeighbors(aq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryAttestations chains the current query on the "attestations" edge.
func (aq *ArtifactQuery) QueryAttestations() *SLSAAttestationQuery {
	query := (&SLSAAttestationClient{config: aq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := aq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := aq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(artifact.Table, artifact.FieldID, selector),
			sqlgraph.To(slsaattestation.Table, slsaattestation.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, artifact.AttestationsTable, artifact.AttestationsPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(aq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QuerySame chains the current query on the "same" edge.
func (aq *ArtifactQuery) QuerySame() *HashEqualQuery {
	query := (&HashEqualClient{config: aq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := aq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := aq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(artifact.Table, artifact.FieldID, selector),
			sqlgraph.To(hashequal.Table, hashequal.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, artifact.SameTable, artifact.SamePrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(aq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first Artifact entity from the query.
// Returns a *NotFoundError when no Artifact was found.
func (aq *ArtifactQuery) First(ctx context.Context) (*Artifact, error) {
	nodes, err := aq.Limit(1).All(setContextOp(ctx, aq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{artifact.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (aq *ArtifactQuery) FirstX(ctx context.Context) *Artifact {
	node, err := aq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first Artifact ID from the query.
// Returns a *NotFoundError when no Artifact ID was found.
func (aq *ArtifactQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = aq.Limit(1).IDs(setContextOp(ctx, aq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{artifact.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (aq *ArtifactQuery) FirstIDX(ctx context.Context) int {
	id, err := aq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single Artifact entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one Artifact entity is found.
// Returns a *NotFoundError when no Artifact entities are found.
func (aq *ArtifactQuery) Only(ctx context.Context) (*Artifact, error) {
	nodes, err := aq.Limit(2).All(setContextOp(ctx, aq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{artifact.Label}
	default:
		return nil, &NotSingularError{artifact.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (aq *ArtifactQuery) OnlyX(ctx context.Context) *Artifact {
	node, err := aq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only Artifact ID in the query.
// Returns a *NotSingularError when more than one Artifact ID is found.
// Returns a *NotFoundError when no entities are found.
func (aq *ArtifactQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = aq.Limit(2).IDs(setContextOp(ctx, aq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{artifact.Label}
	default:
		err = &NotSingularError{artifact.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (aq *ArtifactQuery) OnlyIDX(ctx context.Context) int {
	id, err := aq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of Artifacts.
func (aq *ArtifactQuery) All(ctx context.Context) ([]*Artifact, error) {
	ctx = setContextOp(ctx, aq.ctx, "All")
	if err := aq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*Artifact, *ArtifactQuery]()
	return withInterceptors[[]*Artifact](ctx, aq, qr, aq.inters)
}

// AllX is like All, but panics if an error occurs.
func (aq *ArtifactQuery) AllX(ctx context.Context) []*Artifact {
	nodes, err := aq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of Artifact IDs.
func (aq *ArtifactQuery) IDs(ctx context.Context) (ids []int, err error) {
	if aq.ctx.Unique == nil && aq.path != nil {
		aq.Unique(true)
	}
	ctx = setContextOp(ctx, aq.ctx, "IDs")
	if err = aq.Select(artifact.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (aq *ArtifactQuery) IDsX(ctx context.Context) []int {
	ids, err := aq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (aq *ArtifactQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, aq.ctx, "Count")
	if err := aq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, aq, querierCount[*ArtifactQuery](), aq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (aq *ArtifactQuery) CountX(ctx context.Context) int {
	count, err := aq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (aq *ArtifactQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, aq.ctx, "Exist")
	switch _, err := aq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (aq *ArtifactQuery) ExistX(ctx context.Context) bool {
	exist, err := aq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the ArtifactQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (aq *ArtifactQuery) Clone() *ArtifactQuery {
	if aq == nil {
		return nil
	}
	return &ArtifactQuery{
		config:           aq.config,
		ctx:              aq.ctx.Clone(),
		order:            append([]artifact.OrderOption{}, aq.order...),
		inters:           append([]Interceptor{}, aq.inters...),
		predicates:       append([]predicate.Artifact{}, aq.predicates...),
		withOccurrences:  aq.withOccurrences.Clone(),
		withSbom:         aq.withSbom.Clone(),
		withAttestations: aq.withAttestations.Clone(),
		withSame:         aq.withSame.Clone(),
		// clone intermediate query.
		sql:  aq.sql.Clone(),
		path: aq.path,
	}
}

// WithOccurrences tells the query-builder to eager-load the nodes that are connected to
// the "occurrences" edge. The optional arguments are used to configure the query builder of the edge.
func (aq *ArtifactQuery) WithOccurrences(opts ...func(*OccurrenceQuery)) *ArtifactQuery {
	query := (&OccurrenceClient{config: aq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	aq.withOccurrences = query
	return aq
}

// WithSbom tells the query-builder to eager-load the nodes that are connected to
// the "sbom" edge. The optional arguments are used to configure the query builder of the edge.
func (aq *ArtifactQuery) WithSbom(opts ...func(*BillOfMaterialsQuery)) *ArtifactQuery {
	query := (&BillOfMaterialsClient{config: aq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	aq.withSbom = query
	return aq
}

// WithAttestations tells the query-builder to eager-load the nodes that are connected to
// the "attestations" edge. The optional arguments are used to configure the query builder of the edge.
func (aq *ArtifactQuery) WithAttestations(opts ...func(*SLSAAttestationQuery)) *ArtifactQuery {
	query := (&SLSAAttestationClient{config: aq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	aq.withAttestations = query
	return aq
}

// WithSame tells the query-builder to eager-load the nodes that are connected to
// the "same" edge. The optional arguments are used to configure the query builder of the edge.
func (aq *ArtifactQuery) WithSame(opts ...func(*HashEqualQuery)) *ArtifactQuery {
	query := (&HashEqualClient{config: aq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	aq.withSame = query
	return aq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Algorithm string `json:"algorithm,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.Artifact.Query().
//		GroupBy(artifact.FieldAlgorithm).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (aq *ArtifactQuery) GroupBy(field string, fields ...string) *ArtifactGroupBy {
	aq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &ArtifactGroupBy{build: aq}
	grbuild.flds = &aq.ctx.Fields
	grbuild.label = artifact.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Algorithm string `json:"algorithm,omitempty"`
//	}
//
//	client.Artifact.Query().
//		Select(artifact.FieldAlgorithm).
//		Scan(ctx, &v)
func (aq *ArtifactQuery) Select(fields ...string) *ArtifactSelect {
	aq.ctx.Fields = append(aq.ctx.Fields, fields...)
	sbuild := &ArtifactSelect{ArtifactQuery: aq}
	sbuild.label = artifact.Label
	sbuild.flds, sbuild.scan = &aq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a ArtifactSelect configured with the given aggregations.
func (aq *ArtifactQuery) Aggregate(fns ...AggregateFunc) *ArtifactSelect {
	return aq.Select().Aggregate(fns...)
}

func (aq *ArtifactQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range aq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, aq); err != nil {
				return err
			}
		}
	}
	for _, f := range aq.ctx.Fields {
		if !artifact.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if aq.path != nil {
		prev, err := aq.path(ctx)
		if err != nil {
			return err
		}
		aq.sql = prev
	}
	return nil
}

func (aq *ArtifactQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*Artifact, error) {
	var (
		nodes       = []*Artifact{}
		_spec       = aq.querySpec()
		loadedTypes = [4]bool{
			aq.withOccurrences != nil,
			aq.withSbom != nil,
			aq.withAttestations != nil,
			aq.withSame != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*Artifact).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &Artifact{config: aq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, aq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := aq.withOccurrences; query != nil {
		if err := aq.loadOccurrences(ctx, query, nodes,
			func(n *Artifact) { n.Edges.Occurrences = []*Occurrence{} },
			func(n *Artifact, e *Occurrence) { n.Edges.Occurrences = append(n.Edges.Occurrences, e) }); err != nil {
			return nil, err
		}
	}
	if query := aq.withSbom; query != nil {
		if err := aq.loadSbom(ctx, query, nodes,
			func(n *Artifact) { n.Edges.Sbom = []*BillOfMaterials{} },
			func(n *Artifact, e *BillOfMaterials) { n.Edges.Sbom = append(n.Edges.Sbom, e) }); err != nil {
			return nil, err
		}
	}
	if query := aq.withAttestations; query != nil {
		if err := aq.loadAttestations(ctx, query, nodes,
			func(n *Artifact) { n.Edges.Attestations = []*SLSAAttestation{} },
			func(n *Artifact, e *SLSAAttestation) { n.Edges.Attestations = append(n.Edges.Attestations, e) }); err != nil {
			return nil, err
		}
	}
	if query := aq.withSame; query != nil {
		if err := aq.loadSame(ctx, query, nodes,
			func(n *Artifact) { n.Edges.Same = []*HashEqual{} },
			func(n *Artifact, e *HashEqual) { n.Edges.Same = append(n.Edges.Same, e) }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (aq *ArtifactQuery) loadOccurrences(ctx context.Context, query *OccurrenceQuery, nodes []*Artifact, init func(*Artifact), assign func(*Artifact, *Occurrence)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[int]*Artifact)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	if len(query.ctx.Fields) > 0 {
		query.ctx.AppendFieldOnce(occurrence.FieldArtifactID)
	}
	query.Where(predicate.Occurrence(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(artifact.OccurrencesColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.ArtifactID
		node, ok := nodeids[fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "artifact_id" returned %v for node %v`, fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (aq *ArtifactQuery) loadSbom(ctx context.Context, query *BillOfMaterialsQuery, nodes []*Artifact, init func(*Artifact), assign func(*Artifact, *BillOfMaterials)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[int]*Artifact)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	if len(query.ctx.Fields) > 0 {
		query.ctx.AppendFieldOnce(billofmaterials.FieldArtifactID)
	}
	query.Where(predicate.BillOfMaterials(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(artifact.SbomColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.ArtifactID
		if fk == nil {
			return fmt.Errorf(`foreign-key "artifact_id" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "artifact_id" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (aq *ArtifactQuery) loadAttestations(ctx context.Context, query *SLSAAttestationQuery, nodes []*Artifact, init func(*Artifact), assign func(*Artifact, *SLSAAttestation)) error {
	edgeIDs := make([]driver.Value, len(nodes))
	byID := make(map[int]*Artifact)
	nids := make(map[int]map[*Artifact]struct{})
	for i, node := range nodes {
		edgeIDs[i] = node.ID
		byID[node.ID] = node
		if init != nil {
			init(node)
		}
	}
	query.Where(func(s *sql.Selector) {
		joinT := sql.Table(artifact.AttestationsTable)
		s.Join(joinT).On(s.C(slsaattestation.FieldID), joinT.C(artifact.AttestationsPrimaryKey[0]))
		s.Where(sql.InValues(joinT.C(artifact.AttestationsPrimaryKey[1]), edgeIDs...))
		columns := s.SelectedColumns()
		s.Select(joinT.C(artifact.AttestationsPrimaryKey[1]))
		s.AppendSelect(columns...)
		s.SetDistinct(false)
	})
	if err := query.prepareQuery(ctx); err != nil {
		return err
	}
	qr := QuerierFunc(func(ctx context.Context, q Query) (Value, error) {
		return query.sqlAll(ctx, func(_ context.Context, spec *sqlgraph.QuerySpec) {
			assign := spec.Assign
			values := spec.ScanValues
			spec.ScanValues = func(columns []string) ([]any, error) {
				values, err := values(columns[1:])
				if err != nil {
					return nil, err
				}
				return append([]any{new(sql.NullInt64)}, values...), nil
			}
			spec.Assign = func(columns []string, values []any) error {
				outValue := int(values[0].(*sql.NullInt64).Int64)
				inValue := int(values[1].(*sql.NullInt64).Int64)
				if nids[inValue] == nil {
					nids[inValue] = map[*Artifact]struct{}{byID[outValue]: {}}
					return assign(columns[1:], values[1:])
				}
				nids[inValue][byID[outValue]] = struct{}{}
				return nil
			}
		})
	})
	neighbors, err := withInterceptors[[]*SLSAAttestation](ctx, query, qr, query.inters)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected "attestations" node returned %v`, n.ID)
		}
		for kn := range nodes {
			assign(kn, n)
		}
	}
	return nil
}
func (aq *ArtifactQuery) loadSame(ctx context.Context, query *HashEqualQuery, nodes []*Artifact, init func(*Artifact), assign func(*Artifact, *HashEqual)) error {
	edgeIDs := make([]driver.Value, len(nodes))
	byID := make(map[int]*Artifact)
	nids := make(map[int]map[*Artifact]struct{})
	for i, node := range nodes {
		edgeIDs[i] = node.ID
		byID[node.ID] = node
		if init != nil {
			init(node)
		}
	}
	query.Where(func(s *sql.Selector) {
		joinT := sql.Table(artifact.SameTable)
		s.Join(joinT).On(s.C(hashequal.FieldID), joinT.C(artifact.SamePrimaryKey[0]))
		s.Where(sql.InValues(joinT.C(artifact.SamePrimaryKey[1]), edgeIDs...))
		columns := s.SelectedColumns()
		s.Select(joinT.C(artifact.SamePrimaryKey[1]))
		s.AppendSelect(columns...)
		s.SetDistinct(false)
	})
	if err := query.prepareQuery(ctx); err != nil {
		return err
	}
	qr := QuerierFunc(func(ctx context.Context, q Query) (Value, error) {
		return query.sqlAll(ctx, func(_ context.Context, spec *sqlgraph.QuerySpec) {
			assign := spec.Assign
			values := spec.ScanValues
			spec.ScanValues = func(columns []string) ([]any, error) {
				values, err := values(columns[1:])
				if err != nil {
					return nil, err
				}
				return append([]any{new(sql.NullInt64)}, values...), nil
			}
			spec.Assign = func(columns []string, values []any) error {
				outValue := int(values[0].(*sql.NullInt64).Int64)
				inValue := int(values[1].(*sql.NullInt64).Int64)
				if nids[inValue] == nil {
					nids[inValue] = map[*Artifact]struct{}{byID[outValue]: {}}
					return assign(columns[1:], values[1:])
				}
				nids[inValue][byID[outValue]] = struct{}{}
				return nil
			}
		})
	})
	neighbors, err := withInterceptors[[]*HashEqual](ctx, query, qr, query.inters)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected "same" node returned %v`, n.ID)
		}
		for kn := range nodes {
			assign(kn, n)
		}
	}
	return nil
}

func (aq *ArtifactQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := aq.querySpec()
	_spec.Node.Columns = aq.ctx.Fields
	if len(aq.ctx.Fields) > 0 {
		_spec.Unique = aq.ctx.Unique != nil && *aq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, aq.driver, _spec)
}

func (aq *ArtifactQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(artifact.Table, artifact.Columns, sqlgraph.NewFieldSpec(artifact.FieldID, field.TypeInt))
	_spec.From = aq.sql
	if unique := aq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if aq.path != nil {
		_spec.Unique = true
	}
	if fields := aq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, artifact.FieldID)
		for i := range fields {
			if fields[i] != artifact.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := aq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := aq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := aq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := aq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (aq *ArtifactQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(aq.driver.Dialect())
	t1 := builder.Table(artifact.Table)
	columns := aq.ctx.Fields
	if len(columns) == 0 {
		columns = artifact.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if aq.sql != nil {
		selector = aq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if aq.ctx.Unique != nil && *aq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range aq.predicates {
		p(selector)
	}
	for _, p := range aq.order {
		p(selector)
	}
	if offset := aq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := aq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ArtifactGroupBy is the group-by builder for Artifact entities.
type ArtifactGroupBy struct {
	selector
	build *ArtifactQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (agb *ArtifactGroupBy) Aggregate(fns ...AggregateFunc) *ArtifactGroupBy {
	agb.fns = append(agb.fns, fns...)
	return agb
}

// Scan applies the selector query and scans the result into the given value.
func (agb *ArtifactGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, agb.build.ctx, "GroupBy")
	if err := agb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*ArtifactQuery, *ArtifactGroupBy](ctx, agb.build, agb, agb.build.inters, v)
}

func (agb *ArtifactGroupBy) sqlScan(ctx context.Context, root *ArtifactQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(agb.fns))
	for _, fn := range agb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*agb.flds)+len(agb.fns))
		for _, f := range *agb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*agb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := agb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// ArtifactSelect is the builder for selecting fields of Artifact entities.
type ArtifactSelect struct {
	*ArtifactQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (as *ArtifactSelect) Aggregate(fns ...AggregateFunc) *ArtifactSelect {
	as.fns = append(as.fns, fns...)
	return as
}

// Scan applies the selector query and scans the result into the given value.
func (as *ArtifactSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, as.ctx, "Select")
	if err := as.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*ArtifactQuery, *ArtifactSelect](ctx, as.ArtifactQuery, as, as.inters, v)
}

func (as *ArtifactSelect) sqlScan(ctx context.Context, root *ArtifactQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(as.fns))
	for _, fn := range as.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*as.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := as.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
