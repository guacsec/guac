-- Drop index "certifylegal_package_id_declared_license_discovered_license_att" from table: "certify_legals"
DROP INDEX "certifylegal_package_id_declared_license_discovered_license_att";
-- Drop index "certifylegal_source_id_declared_license_discovered_license_attr" from table: "certify_legals"
DROP INDEX "certifylegal_source_id_declared_license_discovered_license_attr";
-- Create index "certifylegal_package_id_declared_license_discovered_license_jus" to table: "certify_legals"
CREATE UNIQUE INDEX "certifylegal_package_id_declared_license_discovered_license_jus" ON "certify_legals" ("package_id", "declared_license", "discovered_license", "justification", "time_scanned", "origin", "collector", "document_ref", "declared_licenses_hash", "discovered_licenses_hash") WHERE ((package_id IS NOT NULL) AND (source_id IS NULL));
-- Create index "certifylegal_source_id_declared_license_discovered_license_just" to table: "certify_legals"
CREATE UNIQUE INDEX "certifylegal_source_id_declared_license_discovered_license_just" ON "certify_legals" ("source_id", "declared_license", "discovered_license", "justification", "time_scanned", "origin", "collector", "document_ref", "declared_licenses_hash", "discovered_licenses_hash") WHERE ((package_id IS NULL) AND (source_id IS NOT NULL));
