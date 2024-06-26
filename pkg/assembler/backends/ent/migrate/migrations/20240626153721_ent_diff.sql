-- Modify "bill_of_materials" table
ALTER TABLE "bill_of_materials" DROP CONSTRAINT "bill_of_materials_artifacts_artifact", DROP CONSTRAINT "bill_of_materials_package_versions_package", ADD CONSTRAINT "bill_of_materials_artifacts_artifact" FOREIGN KEY ("artifact_id") REFERENCES "artifacts" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, ADD CONSTRAINT "bill_of_materials_package_versions_package" FOREIGN KEY ("package_id") REFERENCES "package_versions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;
-- Modify "certify_vulns" table
ALTER TABLE "certify_vulns" DROP CONSTRAINT "certify_vulns_package_versions_package", DROP CONSTRAINT "certify_vulns_vulnerability_ids_vulnerability", ADD CONSTRAINT "certify_vulns_package_versions_package" FOREIGN KEY ("package_id") REFERENCES "package_versions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, ADD CONSTRAINT "certify_vulns_vulnerability_ids_vulnerability" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability_ids" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;
-- Modify "dependencies" table
ALTER TABLE "dependencies" DROP CONSTRAINT "dependencies_package_names_dependent_package_name", DROP CONSTRAINT "dependencies_package_versions_dependent_package_version", DROP CONSTRAINT "dependencies_package_versions_package", ADD CONSTRAINT "dependencies_package_names_dependent_package_name" FOREIGN KEY ("dependent_package_name_id") REFERENCES "package_names" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, ADD CONSTRAINT "dependencies_package_versions_dependent_package_version" FOREIGN KEY ("dependent_package_version_id") REFERENCES "package_versions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, ADD CONSTRAINT "dependencies_package_versions_package" FOREIGN KEY ("package_id") REFERENCES "package_versions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;
-- Modify "occurrences" table
ALTER TABLE "occurrences" DROP CONSTRAINT "occurrences_artifacts_artifact", DROP CONSTRAINT "occurrences_package_versions_package", DROP CONSTRAINT "occurrences_source_names_source", ADD CONSTRAINT "occurrences_artifacts_artifact" FOREIGN KEY ("artifact_id") REFERENCES "artifacts" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, ADD CONSTRAINT "occurrences_package_versions_package" FOREIGN KEY ("package_id") REFERENCES "package_versions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, ADD CONSTRAINT "occurrences_source_names_source" FOREIGN KEY ("source_id") REFERENCES "source_names" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;
-- Modify "slsa_attestations" table
ALTER TABLE "slsa_attestations" DROP CONSTRAINT "slsa_attestations_artifacts_subject", DROP CONSTRAINT "slsa_attestations_builders_built_by", ADD CONSTRAINT "slsa_attestations_artifacts_subject" FOREIGN KEY ("subject_id") REFERENCES "artifacts" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, ADD CONSTRAINT "slsa_attestations_builders_built_by" FOREIGN KEY ("built_by_id") REFERENCES "builders" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;
