// Code generated by ent, DO NOT EDIT.

package dependency

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldLTE(FieldID, id))
}

// PackageID applies equality check predicate on the "package_id" field. It's identical to PackageIDEQ.
func PackageID(v uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldPackageID, v))
}

// DependentPackageVersionID applies equality check predicate on the "dependent_package_version_id" field. It's identical to DependentPackageVersionIDEQ.
func DependentPackageVersionID(v uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldDependentPackageVersionID, v))
}

// Justification applies equality check predicate on the "justification" field. It's identical to JustificationEQ.
func Justification(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldJustification, v))
}

// Origin applies equality check predicate on the "origin" field. It's identical to OriginEQ.
func Origin(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldOrigin, v))
}

// Collector applies equality check predicate on the "collector" field. It's identical to CollectorEQ.
func Collector(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldCollector, v))
}

// DocumentRef applies equality check predicate on the "document_ref" field. It's identical to DocumentRefEQ.
func DocumentRef(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldDocumentRef, v))
}

// PackageIDEQ applies the EQ predicate on the "package_id" field.
func PackageIDEQ(v uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldPackageID, v))
}

// PackageIDNEQ applies the NEQ predicate on the "package_id" field.
func PackageIDNEQ(v uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldPackageID, v))
}

// PackageIDIn applies the In predicate on the "package_id" field.
func PackageIDIn(vs ...uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldPackageID, vs...))
}

// PackageIDNotIn applies the NotIn predicate on the "package_id" field.
func PackageIDNotIn(vs ...uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldPackageID, vs...))
}

// DependentPackageVersionIDEQ applies the EQ predicate on the "dependent_package_version_id" field.
func DependentPackageVersionIDEQ(v uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldDependentPackageVersionID, v))
}

// DependentPackageVersionIDNEQ applies the NEQ predicate on the "dependent_package_version_id" field.
func DependentPackageVersionIDNEQ(v uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldDependentPackageVersionID, v))
}

// DependentPackageVersionIDIn applies the In predicate on the "dependent_package_version_id" field.
func DependentPackageVersionIDIn(vs ...uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldDependentPackageVersionID, vs...))
}

// DependentPackageVersionIDNotIn applies the NotIn predicate on the "dependent_package_version_id" field.
func DependentPackageVersionIDNotIn(vs ...uuid.UUID) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldDependentPackageVersionID, vs...))
}

// DependencyTypeEQ applies the EQ predicate on the "dependency_type" field.
func DependencyTypeEQ(v DependencyType) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldDependencyType, v))
}

// DependencyTypeNEQ applies the NEQ predicate on the "dependency_type" field.
func DependencyTypeNEQ(v DependencyType) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldDependencyType, v))
}

// DependencyTypeIn applies the In predicate on the "dependency_type" field.
func DependencyTypeIn(vs ...DependencyType) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldDependencyType, vs...))
}

// DependencyTypeNotIn applies the NotIn predicate on the "dependency_type" field.
func DependencyTypeNotIn(vs ...DependencyType) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldDependencyType, vs...))
}

// JustificationEQ applies the EQ predicate on the "justification" field.
func JustificationEQ(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldJustification, v))
}

// JustificationNEQ applies the NEQ predicate on the "justification" field.
func JustificationNEQ(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldJustification, v))
}

// JustificationIn applies the In predicate on the "justification" field.
func JustificationIn(vs ...string) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldJustification, vs...))
}

// JustificationNotIn applies the NotIn predicate on the "justification" field.
func JustificationNotIn(vs ...string) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldJustification, vs...))
}

// JustificationGT applies the GT predicate on the "justification" field.
func JustificationGT(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldGT(FieldJustification, v))
}

// JustificationGTE applies the GTE predicate on the "justification" field.
func JustificationGTE(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldGTE(FieldJustification, v))
}

// JustificationLT applies the LT predicate on the "justification" field.
func JustificationLT(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldLT(FieldJustification, v))
}

// JustificationLTE applies the LTE predicate on the "justification" field.
func JustificationLTE(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldLTE(FieldJustification, v))
}

// JustificationContains applies the Contains predicate on the "justification" field.
func JustificationContains(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldContains(FieldJustification, v))
}

// JustificationHasPrefix applies the HasPrefix predicate on the "justification" field.
func JustificationHasPrefix(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldHasPrefix(FieldJustification, v))
}

// JustificationHasSuffix applies the HasSuffix predicate on the "justification" field.
func JustificationHasSuffix(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldHasSuffix(FieldJustification, v))
}

// JustificationEqualFold applies the EqualFold predicate on the "justification" field.
func JustificationEqualFold(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEqualFold(FieldJustification, v))
}

// JustificationContainsFold applies the ContainsFold predicate on the "justification" field.
func JustificationContainsFold(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldContainsFold(FieldJustification, v))
}

// OriginEQ applies the EQ predicate on the "origin" field.
func OriginEQ(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldOrigin, v))
}

// OriginNEQ applies the NEQ predicate on the "origin" field.
func OriginNEQ(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldOrigin, v))
}

// OriginIn applies the In predicate on the "origin" field.
func OriginIn(vs ...string) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldOrigin, vs...))
}

// OriginNotIn applies the NotIn predicate on the "origin" field.
func OriginNotIn(vs ...string) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldOrigin, vs...))
}

// OriginGT applies the GT predicate on the "origin" field.
func OriginGT(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldGT(FieldOrigin, v))
}

// OriginGTE applies the GTE predicate on the "origin" field.
func OriginGTE(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldGTE(FieldOrigin, v))
}

// OriginLT applies the LT predicate on the "origin" field.
func OriginLT(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldLT(FieldOrigin, v))
}

// OriginLTE applies the LTE predicate on the "origin" field.
func OriginLTE(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldLTE(FieldOrigin, v))
}

// OriginContains applies the Contains predicate on the "origin" field.
func OriginContains(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldContains(FieldOrigin, v))
}

// OriginHasPrefix applies the HasPrefix predicate on the "origin" field.
func OriginHasPrefix(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldHasPrefix(FieldOrigin, v))
}

// OriginHasSuffix applies the HasSuffix predicate on the "origin" field.
func OriginHasSuffix(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldHasSuffix(FieldOrigin, v))
}

// OriginEqualFold applies the EqualFold predicate on the "origin" field.
func OriginEqualFold(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEqualFold(FieldOrigin, v))
}

// OriginContainsFold applies the ContainsFold predicate on the "origin" field.
func OriginContainsFold(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldContainsFold(FieldOrigin, v))
}

// CollectorEQ applies the EQ predicate on the "collector" field.
func CollectorEQ(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldCollector, v))
}

// CollectorNEQ applies the NEQ predicate on the "collector" field.
func CollectorNEQ(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldCollector, v))
}

// CollectorIn applies the In predicate on the "collector" field.
func CollectorIn(vs ...string) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldCollector, vs...))
}

// CollectorNotIn applies the NotIn predicate on the "collector" field.
func CollectorNotIn(vs ...string) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldCollector, vs...))
}

// CollectorGT applies the GT predicate on the "collector" field.
func CollectorGT(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldGT(FieldCollector, v))
}

// CollectorGTE applies the GTE predicate on the "collector" field.
func CollectorGTE(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldGTE(FieldCollector, v))
}

// CollectorLT applies the LT predicate on the "collector" field.
func CollectorLT(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldLT(FieldCollector, v))
}

// CollectorLTE applies the LTE predicate on the "collector" field.
func CollectorLTE(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldLTE(FieldCollector, v))
}

// CollectorContains applies the Contains predicate on the "collector" field.
func CollectorContains(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldContains(FieldCollector, v))
}

// CollectorHasPrefix applies the HasPrefix predicate on the "collector" field.
func CollectorHasPrefix(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldHasPrefix(FieldCollector, v))
}

// CollectorHasSuffix applies the HasSuffix predicate on the "collector" field.
func CollectorHasSuffix(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldHasSuffix(FieldCollector, v))
}

// CollectorEqualFold applies the EqualFold predicate on the "collector" field.
func CollectorEqualFold(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEqualFold(FieldCollector, v))
}

// CollectorContainsFold applies the ContainsFold predicate on the "collector" field.
func CollectorContainsFold(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldContainsFold(FieldCollector, v))
}

// DocumentRefEQ applies the EQ predicate on the "document_ref" field.
func DocumentRefEQ(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldDocumentRef, v))
}

// DocumentRefNEQ applies the NEQ predicate on the "document_ref" field.
func DocumentRefNEQ(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldDocumentRef, v))
}

// DocumentRefIn applies the In predicate on the "document_ref" field.
func DocumentRefIn(vs ...string) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldDocumentRef, vs...))
}

// DocumentRefNotIn applies the NotIn predicate on the "document_ref" field.
func DocumentRefNotIn(vs ...string) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldDocumentRef, vs...))
}

// DocumentRefGT applies the GT predicate on the "document_ref" field.
func DocumentRefGT(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldGT(FieldDocumentRef, v))
}

// DocumentRefGTE applies the GTE predicate on the "document_ref" field.
func DocumentRefGTE(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldGTE(FieldDocumentRef, v))
}

// DocumentRefLT applies the LT predicate on the "document_ref" field.
func DocumentRefLT(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldLT(FieldDocumentRef, v))
}

// DocumentRefLTE applies the LTE predicate on the "document_ref" field.
func DocumentRefLTE(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldLTE(FieldDocumentRef, v))
}

// DocumentRefContains applies the Contains predicate on the "document_ref" field.
func DocumentRefContains(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldContains(FieldDocumentRef, v))
}

// DocumentRefHasPrefix applies the HasPrefix predicate on the "document_ref" field.
func DocumentRefHasPrefix(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldHasPrefix(FieldDocumentRef, v))
}

// DocumentRefHasSuffix applies the HasSuffix predicate on the "document_ref" field.
func DocumentRefHasSuffix(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldHasSuffix(FieldDocumentRef, v))
}

// DocumentRefEqualFold applies the EqualFold predicate on the "document_ref" field.
func DocumentRefEqualFold(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEqualFold(FieldDocumentRef, v))
}

// DocumentRefContainsFold applies the ContainsFold predicate on the "document_ref" field.
func DocumentRefContainsFold(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldContainsFold(FieldDocumentRef, v))
}

// HasPackage applies the HasEdge predicate on the "package" edge.
func HasPackage() predicate.Dependency {
	return predicate.Dependency(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, PackageTable, PackageColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasPackageWith applies the HasEdge predicate on the "package" edge with a given conditions (other predicates).
func HasPackageWith(preds ...predicate.PackageVersion) predicate.Dependency {
	return predicate.Dependency(func(s *sql.Selector) {
		step := newPackageStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasDependentPackageVersion applies the HasEdge predicate on the "dependent_package_version" edge.
func HasDependentPackageVersion() predicate.Dependency {
	return predicate.Dependency(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, DependentPackageVersionTable, DependentPackageVersionColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasDependentPackageVersionWith applies the HasEdge predicate on the "dependent_package_version" edge with a given conditions (other predicates).
func HasDependentPackageVersionWith(preds ...predicate.PackageVersion) predicate.Dependency {
	return predicate.Dependency(func(s *sql.Selector) {
		step := newDependentPackageVersionStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasIncludedInSboms applies the HasEdge predicate on the "included_in_sboms" edge.
func HasIncludedInSboms() predicate.Dependency {
	return predicate.Dependency(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, IncludedInSbomsTable, IncludedInSbomsPrimaryKey...),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasIncludedInSbomsWith applies the HasEdge predicate on the "included_in_sboms" edge with a given conditions (other predicates).
func HasIncludedInSbomsWith(preds ...predicate.BillOfMaterials) predicate.Dependency {
	return predicate.Dependency(func(s *sql.Selector) {
		step := newIncludedInSbomsStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Dependency) predicate.Dependency {
	return predicate.Dependency(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Dependency) predicate.Dependency {
	return predicate.Dependency(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.Dependency) predicate.Dependency {
	return predicate.Dependency(sql.NotPredicates(p))
}
