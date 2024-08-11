-- Create index "billofmaterials_artifact_id" to table: "bill_of_materials"
CREATE INDEX "billofmaterials_artifact_id" ON "bill_of_materials" ("artifact_id") WHERE ((package_id IS NULL) AND (artifact_id IS NOT NULL));
-- Create index "billofmaterials_package_id" to table: "bill_of_materials"
CREATE INDEX "billofmaterials_package_id" ON "bill_of_materials" ("package_id") WHERE ((package_id IS NOT NULL) AND (artifact_id IS NULL));
-- Create index "certifylegal_package_id" to table: "certify_legals"
CREATE INDEX "certifylegal_package_id" ON "certify_legals" ("package_id") WHERE ((package_id IS NOT NULL) AND (source_id IS NULL));
-- Create index "dependency_dependent_package_version_id" to table: "dependencies"
CREATE INDEX "dependency_dependent_package_version_id" ON "dependencies" ("dependent_package_version_id");
-- Create index "occurrence_artifact_id" to table: "occurrences"
CREATE INDEX "occurrence_artifact_id" ON "occurrences" ("artifact_id");
-- Create index "query_occurrence_package_id" to table: "occurrences"
CREATE INDEX "query_occurrence_package_id" ON "occurrences" ("package_id") WHERE ((package_id IS NOT NULL) AND (source_id IS NULL));
