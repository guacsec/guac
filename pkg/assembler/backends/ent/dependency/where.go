// Code generated by ent, DO NOT EDIT.

package dependency

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.Dependency {
	return predicate.Dependency(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.Dependency {
	return predicate.Dependency(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.Dependency {
	return predicate.Dependency(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.Dependency {
	return predicate.Dependency(sql.FieldLTE(FieldID, id))
}

// PackageID applies equality check predicate on the "package_id" field. It's identical to PackageIDEQ.
func PackageID(v int) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldPackageID, v))
}

// DependentPackageID applies equality check predicate on the "dependent_package_id" field. It's identical to DependentPackageIDEQ.
func DependentPackageID(v int) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldDependentPackageID, v))
}

// VersionRange applies equality check predicate on the "version_range" field. It's identical to VersionRangeEQ.
func VersionRange(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldVersionRange, v))
}

// DependencyType applies equality check predicate on the "dependency_type" field. It's identical to DependencyTypeEQ.
func DependencyType(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldDependencyType, v))
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

// PackageIDEQ applies the EQ predicate on the "package_id" field.
func PackageIDEQ(v int) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldPackageID, v))
}

// PackageIDNEQ applies the NEQ predicate on the "package_id" field.
func PackageIDNEQ(v int) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldPackageID, v))
}

// PackageIDIn applies the In predicate on the "package_id" field.
func PackageIDIn(vs ...int) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldPackageID, vs...))
}

// PackageIDNotIn applies the NotIn predicate on the "package_id" field.
func PackageIDNotIn(vs ...int) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldPackageID, vs...))
}

// DependentPackageIDEQ applies the EQ predicate on the "dependent_package_id" field.
func DependentPackageIDEQ(v int) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldDependentPackageID, v))
}

// DependentPackageIDNEQ applies the NEQ predicate on the "dependent_package_id" field.
func DependentPackageIDNEQ(v int) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldDependentPackageID, v))
}

// DependentPackageIDIn applies the In predicate on the "dependent_package_id" field.
func DependentPackageIDIn(vs ...int) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldDependentPackageID, vs...))
}

// DependentPackageIDNotIn applies the NotIn predicate on the "dependent_package_id" field.
func DependentPackageIDNotIn(vs ...int) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldDependentPackageID, vs...))
}

// VersionRangeEQ applies the EQ predicate on the "version_range" field.
func VersionRangeEQ(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldVersionRange, v))
}

// VersionRangeNEQ applies the NEQ predicate on the "version_range" field.
func VersionRangeNEQ(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldVersionRange, v))
}

// VersionRangeIn applies the In predicate on the "version_range" field.
func VersionRangeIn(vs ...string) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldVersionRange, vs...))
}

// VersionRangeNotIn applies the NotIn predicate on the "version_range" field.
func VersionRangeNotIn(vs ...string) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldVersionRange, vs...))
}

// VersionRangeGT applies the GT predicate on the "version_range" field.
func VersionRangeGT(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldGT(FieldVersionRange, v))
}

// VersionRangeGTE applies the GTE predicate on the "version_range" field.
func VersionRangeGTE(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldGTE(FieldVersionRange, v))
}

// VersionRangeLT applies the LT predicate on the "version_range" field.
func VersionRangeLT(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldLT(FieldVersionRange, v))
}

// VersionRangeLTE applies the LTE predicate on the "version_range" field.
func VersionRangeLTE(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldLTE(FieldVersionRange, v))
}

// VersionRangeContains applies the Contains predicate on the "version_range" field.
func VersionRangeContains(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldContains(FieldVersionRange, v))
}

// VersionRangeHasPrefix applies the HasPrefix predicate on the "version_range" field.
func VersionRangeHasPrefix(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldHasPrefix(FieldVersionRange, v))
}

// VersionRangeHasSuffix applies the HasSuffix predicate on the "version_range" field.
func VersionRangeHasSuffix(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldHasSuffix(FieldVersionRange, v))
}

// VersionRangeEqualFold applies the EqualFold predicate on the "version_range" field.
func VersionRangeEqualFold(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEqualFold(FieldVersionRange, v))
}

// VersionRangeContainsFold applies the ContainsFold predicate on the "version_range" field.
func VersionRangeContainsFold(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldContainsFold(FieldVersionRange, v))
}

// DependencyTypeEQ applies the EQ predicate on the "dependency_type" field.
func DependencyTypeEQ(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEQ(FieldDependencyType, v))
}

// DependencyTypeNEQ applies the NEQ predicate on the "dependency_type" field.
func DependencyTypeNEQ(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldNEQ(FieldDependencyType, v))
}

// DependencyTypeIn applies the In predicate on the "dependency_type" field.
func DependencyTypeIn(vs ...string) predicate.Dependency {
	return predicate.Dependency(sql.FieldIn(FieldDependencyType, vs...))
}

// DependencyTypeNotIn applies the NotIn predicate on the "dependency_type" field.
func DependencyTypeNotIn(vs ...string) predicate.Dependency {
	return predicate.Dependency(sql.FieldNotIn(FieldDependencyType, vs...))
}

// DependencyTypeGT applies the GT predicate on the "dependency_type" field.
func DependencyTypeGT(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldGT(FieldDependencyType, v))
}

// DependencyTypeGTE applies the GTE predicate on the "dependency_type" field.
func DependencyTypeGTE(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldGTE(FieldDependencyType, v))
}

// DependencyTypeLT applies the LT predicate on the "dependency_type" field.
func DependencyTypeLT(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldLT(FieldDependencyType, v))
}

// DependencyTypeLTE applies the LTE predicate on the "dependency_type" field.
func DependencyTypeLTE(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldLTE(FieldDependencyType, v))
}

// DependencyTypeContains applies the Contains predicate on the "dependency_type" field.
func DependencyTypeContains(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldContains(FieldDependencyType, v))
}

// DependencyTypeHasPrefix applies the HasPrefix predicate on the "dependency_type" field.
func DependencyTypeHasPrefix(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldHasPrefix(FieldDependencyType, v))
}

// DependencyTypeHasSuffix applies the HasSuffix predicate on the "dependency_type" field.
func DependencyTypeHasSuffix(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldHasSuffix(FieldDependencyType, v))
}

// DependencyTypeEqualFold applies the EqualFold predicate on the "dependency_type" field.
func DependencyTypeEqualFold(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldEqualFold(FieldDependencyType, v))
}

// DependencyTypeContainsFold applies the ContainsFold predicate on the "dependency_type" field.
func DependencyTypeContainsFold(v string) predicate.Dependency {
	return predicate.Dependency(sql.FieldContainsFold(FieldDependencyType, v))
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

// HasDependentPackage applies the HasEdge predicate on the "dependent_package" edge.
func HasDependentPackage() predicate.Dependency {
	return predicate.Dependency(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, DependentPackageTable, DependentPackageColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasDependentPackageWith applies the HasEdge predicate on the "dependent_package" edge with a given conditions (other predicates).
func HasDependentPackageWith(preds ...predicate.PackageName) predicate.Dependency {
	return predicate.Dependency(func(s *sql.Selector) {
		step := newDependentPackageStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Dependency) predicate.Dependency {
	return predicate.Dependency(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Dependency) predicate.Dependency {
	return predicate.Dependency(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for i, p := range predicates {
			if i > 0 {
				s1.Or()
			}
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Not applies the not operator on the given predicate.
func Not(p predicate.Dependency) predicate.Dependency {
	return predicate.Dependency(func(s *sql.Selector) {
		p(s.Not())
	})
}
