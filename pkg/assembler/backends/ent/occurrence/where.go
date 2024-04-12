// Code generated by ent, DO NOT EDIT.

package occurrence

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldLTE(FieldID, id))
}

// ArtifactID applies equality check predicate on the "artifact_id" field. It's identical to ArtifactIDEQ.
func ArtifactID(v uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldArtifactID, v))
}

// Justification applies equality check predicate on the "justification" field. It's identical to JustificationEQ.
func Justification(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldJustification, v))
}

// Origin applies equality check predicate on the "origin" field. It's identical to OriginEQ.
func Origin(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldOrigin, v))
}

// Collector applies equality check predicate on the "collector" field. It's identical to CollectorEQ.
func Collector(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldCollector, v))
}

// DocumentRef applies equality check predicate on the "document_ref" field. It's identical to DocumentRefEQ.
func DocumentRef(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldDocumentRef, v))
}

// SourceID applies equality check predicate on the "source_id" field. It's identical to SourceIDEQ.
func SourceID(v uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldSourceID, v))
}

// PackageID applies equality check predicate on the "package_id" field. It's identical to PackageIDEQ.
func PackageID(v uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldPackageID, v))
}

// ArtifactIDEQ applies the EQ predicate on the "artifact_id" field.
func ArtifactIDEQ(v uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldArtifactID, v))
}

// ArtifactIDNEQ applies the NEQ predicate on the "artifact_id" field.
func ArtifactIDNEQ(v uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNEQ(FieldArtifactID, v))
}

// ArtifactIDIn applies the In predicate on the "artifact_id" field.
func ArtifactIDIn(vs ...uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldIn(FieldArtifactID, vs...))
}

// ArtifactIDNotIn applies the NotIn predicate on the "artifact_id" field.
func ArtifactIDNotIn(vs ...uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNotIn(FieldArtifactID, vs...))
}

// JustificationEQ applies the EQ predicate on the "justification" field.
func JustificationEQ(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldJustification, v))
}

// JustificationNEQ applies the NEQ predicate on the "justification" field.
func JustificationNEQ(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNEQ(FieldJustification, v))
}

// JustificationIn applies the In predicate on the "justification" field.
func JustificationIn(vs ...string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldIn(FieldJustification, vs...))
}

// JustificationNotIn applies the NotIn predicate on the "justification" field.
func JustificationNotIn(vs ...string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNotIn(FieldJustification, vs...))
}

// JustificationGT applies the GT predicate on the "justification" field.
func JustificationGT(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldGT(FieldJustification, v))
}

// JustificationGTE applies the GTE predicate on the "justification" field.
func JustificationGTE(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldGTE(FieldJustification, v))
}

// JustificationLT applies the LT predicate on the "justification" field.
func JustificationLT(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldLT(FieldJustification, v))
}

// JustificationLTE applies the LTE predicate on the "justification" field.
func JustificationLTE(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldLTE(FieldJustification, v))
}

// JustificationContains applies the Contains predicate on the "justification" field.
func JustificationContains(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldContains(FieldJustification, v))
}

// JustificationHasPrefix applies the HasPrefix predicate on the "justification" field.
func JustificationHasPrefix(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldHasPrefix(FieldJustification, v))
}

// JustificationHasSuffix applies the HasSuffix predicate on the "justification" field.
func JustificationHasSuffix(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldHasSuffix(FieldJustification, v))
}

// JustificationEqualFold applies the EqualFold predicate on the "justification" field.
func JustificationEqualFold(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEqualFold(FieldJustification, v))
}

// JustificationContainsFold applies the ContainsFold predicate on the "justification" field.
func JustificationContainsFold(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldContainsFold(FieldJustification, v))
}

// OriginEQ applies the EQ predicate on the "origin" field.
func OriginEQ(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldOrigin, v))
}

// OriginNEQ applies the NEQ predicate on the "origin" field.
func OriginNEQ(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNEQ(FieldOrigin, v))
}

// OriginIn applies the In predicate on the "origin" field.
func OriginIn(vs ...string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldIn(FieldOrigin, vs...))
}

// OriginNotIn applies the NotIn predicate on the "origin" field.
func OriginNotIn(vs ...string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNotIn(FieldOrigin, vs...))
}

// OriginGT applies the GT predicate on the "origin" field.
func OriginGT(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldGT(FieldOrigin, v))
}

// OriginGTE applies the GTE predicate on the "origin" field.
func OriginGTE(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldGTE(FieldOrigin, v))
}

// OriginLT applies the LT predicate on the "origin" field.
func OriginLT(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldLT(FieldOrigin, v))
}

// OriginLTE applies the LTE predicate on the "origin" field.
func OriginLTE(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldLTE(FieldOrigin, v))
}

// OriginContains applies the Contains predicate on the "origin" field.
func OriginContains(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldContains(FieldOrigin, v))
}

// OriginHasPrefix applies the HasPrefix predicate on the "origin" field.
func OriginHasPrefix(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldHasPrefix(FieldOrigin, v))
}

// OriginHasSuffix applies the HasSuffix predicate on the "origin" field.
func OriginHasSuffix(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldHasSuffix(FieldOrigin, v))
}

// OriginEqualFold applies the EqualFold predicate on the "origin" field.
func OriginEqualFold(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEqualFold(FieldOrigin, v))
}

// OriginContainsFold applies the ContainsFold predicate on the "origin" field.
func OriginContainsFold(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldContainsFold(FieldOrigin, v))
}

// CollectorEQ applies the EQ predicate on the "collector" field.
func CollectorEQ(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldCollector, v))
}

// CollectorNEQ applies the NEQ predicate on the "collector" field.
func CollectorNEQ(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNEQ(FieldCollector, v))
}

// CollectorIn applies the In predicate on the "collector" field.
func CollectorIn(vs ...string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldIn(FieldCollector, vs...))
}

// CollectorNotIn applies the NotIn predicate on the "collector" field.
func CollectorNotIn(vs ...string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNotIn(FieldCollector, vs...))
}

// CollectorGT applies the GT predicate on the "collector" field.
func CollectorGT(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldGT(FieldCollector, v))
}

// CollectorGTE applies the GTE predicate on the "collector" field.
func CollectorGTE(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldGTE(FieldCollector, v))
}

// CollectorLT applies the LT predicate on the "collector" field.
func CollectorLT(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldLT(FieldCollector, v))
}

// CollectorLTE applies the LTE predicate on the "collector" field.
func CollectorLTE(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldLTE(FieldCollector, v))
}

// CollectorContains applies the Contains predicate on the "collector" field.
func CollectorContains(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldContains(FieldCollector, v))
}

// CollectorHasPrefix applies the HasPrefix predicate on the "collector" field.
func CollectorHasPrefix(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldHasPrefix(FieldCollector, v))
}

// CollectorHasSuffix applies the HasSuffix predicate on the "collector" field.
func CollectorHasSuffix(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldHasSuffix(FieldCollector, v))
}

// CollectorEqualFold applies the EqualFold predicate on the "collector" field.
func CollectorEqualFold(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEqualFold(FieldCollector, v))
}

// CollectorContainsFold applies the ContainsFold predicate on the "collector" field.
func CollectorContainsFold(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldContainsFold(FieldCollector, v))
}

// DocumentRefEQ applies the EQ predicate on the "document_ref" field.
func DocumentRefEQ(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldDocumentRef, v))
}

// DocumentRefNEQ applies the NEQ predicate on the "document_ref" field.
func DocumentRefNEQ(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNEQ(FieldDocumentRef, v))
}

// DocumentRefIn applies the In predicate on the "document_ref" field.
func DocumentRefIn(vs ...string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldIn(FieldDocumentRef, vs...))
}

// DocumentRefNotIn applies the NotIn predicate on the "document_ref" field.
func DocumentRefNotIn(vs ...string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNotIn(FieldDocumentRef, vs...))
}

// DocumentRefGT applies the GT predicate on the "document_ref" field.
func DocumentRefGT(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldGT(FieldDocumentRef, v))
}

// DocumentRefGTE applies the GTE predicate on the "document_ref" field.
func DocumentRefGTE(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldGTE(FieldDocumentRef, v))
}

// DocumentRefLT applies the LT predicate on the "document_ref" field.
func DocumentRefLT(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldLT(FieldDocumentRef, v))
}

// DocumentRefLTE applies the LTE predicate on the "document_ref" field.
func DocumentRefLTE(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldLTE(FieldDocumentRef, v))
}

// DocumentRefContains applies the Contains predicate on the "document_ref" field.
func DocumentRefContains(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldContains(FieldDocumentRef, v))
}

// DocumentRefHasPrefix applies the HasPrefix predicate on the "document_ref" field.
func DocumentRefHasPrefix(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldHasPrefix(FieldDocumentRef, v))
}

// DocumentRefHasSuffix applies the HasSuffix predicate on the "document_ref" field.
func DocumentRefHasSuffix(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldHasSuffix(FieldDocumentRef, v))
}

// DocumentRefEqualFold applies the EqualFold predicate on the "document_ref" field.
func DocumentRefEqualFold(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEqualFold(FieldDocumentRef, v))
}

// DocumentRefContainsFold applies the ContainsFold predicate on the "document_ref" field.
func DocumentRefContainsFold(v string) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldContainsFold(FieldDocumentRef, v))
}

// SourceIDEQ applies the EQ predicate on the "source_id" field.
func SourceIDEQ(v uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldSourceID, v))
}

// SourceIDNEQ applies the NEQ predicate on the "source_id" field.
func SourceIDNEQ(v uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNEQ(FieldSourceID, v))
}

// SourceIDIn applies the In predicate on the "source_id" field.
func SourceIDIn(vs ...uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldIn(FieldSourceID, vs...))
}

// SourceIDNotIn applies the NotIn predicate on the "source_id" field.
func SourceIDNotIn(vs ...uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNotIn(FieldSourceID, vs...))
}

// SourceIDIsNil applies the IsNil predicate on the "source_id" field.
func SourceIDIsNil() predicate.Occurrence {
	return predicate.Occurrence(sql.FieldIsNull(FieldSourceID))
}

// SourceIDNotNil applies the NotNil predicate on the "source_id" field.
func SourceIDNotNil() predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNotNull(FieldSourceID))
}

// PackageIDEQ applies the EQ predicate on the "package_id" field.
func PackageIDEQ(v uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldEQ(FieldPackageID, v))
}

// PackageIDNEQ applies the NEQ predicate on the "package_id" field.
func PackageIDNEQ(v uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNEQ(FieldPackageID, v))
}

// PackageIDIn applies the In predicate on the "package_id" field.
func PackageIDIn(vs ...uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldIn(FieldPackageID, vs...))
}

// PackageIDNotIn applies the NotIn predicate on the "package_id" field.
func PackageIDNotIn(vs ...uuid.UUID) predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNotIn(FieldPackageID, vs...))
}

// PackageIDIsNil applies the IsNil predicate on the "package_id" field.
func PackageIDIsNil() predicate.Occurrence {
	return predicate.Occurrence(sql.FieldIsNull(FieldPackageID))
}

// PackageIDNotNil applies the NotNil predicate on the "package_id" field.
func PackageIDNotNil() predicate.Occurrence {
	return predicate.Occurrence(sql.FieldNotNull(FieldPackageID))
}

// HasArtifact applies the HasEdge predicate on the "artifact" edge.
func HasArtifact() predicate.Occurrence {
	return predicate.Occurrence(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, ArtifactTable, ArtifactColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasArtifactWith applies the HasEdge predicate on the "artifact" edge with a given conditions (other predicates).
func HasArtifactWith(preds ...predicate.Artifact) predicate.Occurrence {
	return predicate.Occurrence(func(s *sql.Selector) {
		step := newArtifactStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasPackage applies the HasEdge predicate on the "package" edge.
func HasPackage() predicate.Occurrence {
	return predicate.Occurrence(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, PackageTable, PackageColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasPackageWith applies the HasEdge predicate on the "package" edge with a given conditions (other predicates).
func HasPackageWith(preds ...predicate.PackageVersion) predicate.Occurrence {
	return predicate.Occurrence(func(s *sql.Selector) {
		step := newPackageStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasSource applies the HasEdge predicate on the "source" edge.
func HasSource() predicate.Occurrence {
	return predicate.Occurrence(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, SourceTable, SourceColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasSourceWith applies the HasEdge predicate on the "source" edge with a given conditions (other predicates).
func HasSourceWith(preds ...predicate.SourceName) predicate.Occurrence {
	return predicate.Occurrence(func(s *sql.Selector) {
		step := newSourceStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasIncludedInSboms applies the HasEdge predicate on the "included_in_sboms" edge.
func HasIncludedInSboms() predicate.Occurrence {
	return predicate.Occurrence(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, IncludedInSbomsTable, IncludedInSbomsPrimaryKey...),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasIncludedInSbomsWith applies the HasEdge predicate on the "included_in_sboms" edge with a given conditions (other predicates).
func HasIncludedInSbomsWith(preds ...predicate.BillOfMaterials) predicate.Occurrence {
	return predicate.Occurrence(func(s *sql.Selector) {
		step := newIncludedInSbomsStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Occurrence) predicate.Occurrence {
	return predicate.Occurrence(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Occurrence) predicate.Occurrence {
	return predicate.Occurrence(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.Occurrence) predicate.Occurrence {
	return predicate.Occurrence(sql.NotPredicates(p))
}
