-- Change ENT auto-migration index name from "certifylegal_package_id_declar_37fd118fe84f0a1eb9042a047d066a77" to "certifylegal_package_id_declared_license_discovered_license_att" from table: "certify_legals"
ALTER INDEX IF EXISTS "certifylegal_package_id_declar_37fd118fe84f0a1eb9042a047d066a77" RENAME TO "certifylegal_package_id_declared_license_discovered_license_att";
-- Change ENT auto-migration index name from "certifylegal_source_id_declare_7172c32e012f5a3f84156bd57473bcd2" to "certifylegal_source_id_declared_license_discovered_license_attr" from table: "certify_legals"
ALTER INDEX IF EXISTS "certifylegal_source_id_declare_7172c32e012f5a3f84156bd57473bcd2" RENAME TO "certifylegal_source_id_declared_license_discovered_license_attr";
-- Drop index "certifylegal_package_id_declared_license_discovered_license_att" from table: "certify_legals"
DROP INDEX "certifylegal_package_id_declared_license_discovered_license_att";
-- Drop index "certifylegal_source_id_declared_license_discovered_license_attr" from table: "certify_legals"
DROP INDEX "certifylegal_source_id_declared_license_discovered_license_attr";
-- Create index "certifylegal_package_id_declared_license_discovered_license_jus" to table: "certify_legals"
CREATE UNIQUE INDEX "certifylegal_package_id_declared_license_discovered_license_jus" ON "certify_legals" ("package_id", "declared_license", "discovered_license", "justification", "time_scanned", "origin", "collector", "document_ref", "declared_licenses_hash", "discovered_licenses_hash") WHERE ((package_id IS NOT NULL) AND (source_id IS NULL));
-- Create index "certifylegal_source_id_declared_license_discovered_license_just" to table: "certify_legals"
CREATE UNIQUE INDEX "certifylegal_source_id_declared_license_discovered_license_just" ON "certify_legals" ("source_id", "declared_license", "discovered_license", "justification", "time_scanned", "origin", "collector", "document_ref", "declared_licenses_hash", "discovered_licenses_hash") WHERE ((package_id IS NULL) AND (source_id IS NOT NULL));
