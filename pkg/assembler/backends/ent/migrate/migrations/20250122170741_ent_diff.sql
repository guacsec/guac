-- Drop index "certifyvuln_db_uri_db_version_scanner_uri_scanner_version_origi" from table: "certify_vulns"
DROP INDEX "certifyvuln_db_uri_db_version_scanner_uri_scanner_version_origi";
-- Create index "certifyvuln_package_id_vulnerability_id_collector_scanner_uri_s" to table: "certify_vulns"
CREATE UNIQUE INDEX "certifyvuln_package_id_vulnerability_id_collector_scanner_uri_s" ON "certify_vulns" ("package_id", "vulnerability_id", "collector", "scanner_uri", "scanner_version", "origin", "db_uri", "db_version");
