-- Modify "dependencies" table
ALTER TABLE "dependencies" DROP COLUMN "version_range", DROP COLUMN "dependent_package_name_id";
-- Create index "dependency_dependency_type_justification_origin_collector_docum" to table: "dependencies"
CREATE UNIQUE INDEX "dependency_dependency_type_justification_origin_collector_docum" ON "dependencies" ("dependency_type", "justification", "origin", "collector", "document_ref", "package_id", "dependent_package_version_id");
