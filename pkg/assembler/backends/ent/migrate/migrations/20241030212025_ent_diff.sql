-- Create index "certifylegal_package_id_declared_licenses_hash_discovered_licen" to table: "certify_legals"
CREATE INDEX "certifylegal_package_id_declared_licenses_hash_discovered_licen" ON "certify_legals" ("package_id", "declared_licenses_hash", "discovered_licenses_hash", "time_scanned") WHERE ((package_id IS NOT NULL) AND (source_id IS NULL));
-- Create index "certifyvuln_vulnerability_id_package_id_time_scanned" to table: "certify_vulns"
CREATE INDEX "certifyvuln_vulnerability_id_package_id_time_scanned" ON "certify_vulns" ("vulnerability_id", "package_id", "time_scanned");
