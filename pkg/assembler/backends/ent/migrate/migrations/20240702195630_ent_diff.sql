-- Create index "certifyvuln_package_id" to table: "certify_vulns"
CREATE INDEX "certifyvuln_package_id" ON "certify_vulns" ("package_id");
-- Create index "vulnerabilityid_type" to table: "vulnerability_ids"
CREATE INDEX "vulnerabilityid_type" ON "vulnerability_ids" ("type");
