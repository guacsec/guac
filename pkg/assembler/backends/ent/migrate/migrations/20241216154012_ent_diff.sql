-- Drop index "vex_artifact_id" from table: "certify_vexes"
DROP INDEX "vex_artifact_id";
-- Drop index "vex_package_id" from table: "certify_vexes"
DROP INDEX "vex_package_id";
-- Create index "vex_artifact_id" to table: "certify_vexes"
CREATE UNIQUE INDEX "vex_artifact_id" ON "certify_vexes" ("known_since", "justification", "status", "origin", "collector", "document_ref", "vulnerability_id", "package_id") WHERE (artifact_id IS NULL);
-- Create index "vex_package_id" to table: "certify_vexes"
CREATE UNIQUE INDEX "vex_package_id" ON "certify_vexes" ("known_since", "justification", "status", "origin", "collector", "document_ref", "vulnerability_id", "artifact_id") WHERE (package_id IS NULL);
