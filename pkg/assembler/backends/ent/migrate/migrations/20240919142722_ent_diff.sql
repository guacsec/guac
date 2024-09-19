-- Drop index "certifylegal_package_id_declared_license_discovered_license_jus" from table: "certify_legals"
DROP INDEX "certifylegal_package_id_declared_license_discovered_license_jus";
-- Drop index "certifylegal_source_id_declared_license_discovered_license_just" from table: "certify_legals"
DROP INDEX "certifylegal_source_id_declared_license_discovered_license_just";
-- Create index "certifylegal_package_id_declared_license_justification_time_sca" to table: "certify_legals"
CREATE UNIQUE INDEX "certifylegal_package_id_declared_license_justification_time_sca" ON "certify_legals" ("package_id", "declared_license", "justification", "time_scanned", "origin", "collector", "document_ref", "declared_licenses_hash", "discovered_licenses_hash") WHERE ((package_id IS NOT NULL) AND (source_id IS NULL));
-- Create index "certifylegal_source_id_declared_license_justification_time_scan" to table: "certify_legals"
CREATE UNIQUE INDEX "certifylegal_source_id_declared_license_justification_time_scan" ON "certify_legals" ("source_id", "declared_license", "justification", "time_scanned", "origin", "collector", "document_ref", "declared_licenses_hash", "discovered_licenses_hash") WHERE ((package_id IS NULL) AND (source_id IS NOT NULL));
