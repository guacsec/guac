-- Truncate all of the data and remove older certify legal entries
TRUNCATE certify_legals RESTART IDENTITY CASCADE;
-- Truncate all of the data and remove older certify vuln entries
TRUNCATE certify_vulns RESTART IDENTITY CASCADE;
-- Change ENT auto-migration index name from "certifylegal_package_id_declar_37fd118fe84f0a1eb9042a047d066a77" to "certifylegal_package_id_declared_license_discovered_license_att" from table: "certify_legals"
ALTER INDEX IF EXISTS "certifyvuln_db_uri_db_version__21c35a4e5f38654fa77920fb7bbb325c" RENAME TO "certifyvuln_db_uri_db_version_scanner_uri_scanner_version_origi";
-- Drop index "certifyvuln_db_uri_db_version_scanner_uri_scanner_version_origi" from table: "certify_vulns"
DROP INDEX "certifyvuln_db_uri_db_version_scanner_uri_scanner_version_origi";
-- Create index "certifyvuln_package_id_vulnerability_id_collector_scanner_uri_s" to table: "certify_vulns"
CREATE UNIQUE INDEX "certifyvuln_package_id_vulnerability_id_collector_scanner_uri_s" ON "certify_vulns" ("package_id", "vulnerability_id", "collector", "scanner_uri", "scanner_version", "origin", "db_uri", "db_version");
-- Drop index "certifylegal_package_id_declared_license_justification_time_sca" from table: "certify_legals"
DROP INDEX "certifylegal_package_id_declared_license_justification_time_sca";
-- Drop index "certifylegal_source_id_declared_license_justification_time_scan" from table: "certify_legals"
DROP INDEX "certifylegal_source_id_declared_license_justification_time_scan";
-- Create index "cl_pkg_id" to table: "certify_legals"
CREATE UNIQUE INDEX "cl_pkg_id" ON "certify_legals" ("declared_license", "justification", "origin", "collector", "declared_licenses_hash", "discovered_licenses_hash", "package_id") WHERE ((package_id IS NOT NULL) AND (source_id IS NULL));
-- Create index "cl_source_id" to table: "certify_legals"
CREATE UNIQUE INDEX "cl_source_id" ON "certify_legals" ("declared_license", "justification", "origin", "collector", "declared_licenses_hash", "discovered_licenses_hash", "source_id") WHERE ((package_id IS NULL) AND (source_id IS NOT NULL));
