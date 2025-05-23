-- Rename an index from "dependency_dependency_type_justification_origin_collector_docum" to "dependency_dependency_type_jus_2ed522bad5bbd1bbb0f36367067b1146"
ALTER INDEX "dependency_dependency_type_justification_origin_collector_docum" RENAME TO "dependency_dependency_type_jus_2ed522bad5bbd1bbb0f36367067b1146";
-- Rename an index from "certification_type_justification_origin_collector_artifact_id_k" to "certification_type_justificati_e71e1f69147e5d0ef7f614cb12b42373"
ALTER INDEX "certification_type_justification_origin_collector_artifact_id_k" RENAME TO "certification_type_justificati_e71e1f69147e5d0ef7f614cb12b42373";
-- Rename an index from "certification_type_justification_origin_collector_package_name_" to "certification_type_justificati_050322ac123e59b56b741a07ea26df53"
ALTER INDEX "certification_type_justification_origin_collector_package_name_" RENAME TO "certification_type_justificati_050322ac123e59b56b741a07ea26df53";
-- Rename an index from "certification_type_justification_origin_collector_package_versi" to "certification_type_justificati_c6d282e2f14094c4106b3d2b0ac979f4"
ALTER INDEX "certification_type_justification_origin_collector_package_versi" RENAME TO "certification_type_justificati_c6d282e2f14094c4106b3d2b0ac979f4";
-- Rename an index from "certification_type_justification_origin_collector_source_id_kno" to "certification_type_justificati_a82272635ecbc67a1e08d7bed937351b"
ALTER INDEX "certification_type_justification_origin_collector_source_id_kno" RENAME TO "certification_type_justificati_a82272635ecbc67a1e08d7bed937351b";
-- Rename an index from "certifylegal_package_id_declared_licenses_hash_discovered_licen" to "certifylegal_package_id_declar_5cf92a2af47b01c0e4f4d3d5098839a1"
ALTER INDEX "certifylegal_package_id_declared_licenses_hash_discovered_licen" RENAME TO "certifylegal_package_id_declar_5cf92a2af47b01c0e4f4d3d5098839a1";
-- Rename an index from "certifyscorecard_source_id_origin_collector_scorecard_version_s" to "certifyscorecard_source_id_ori_508fb6b816b5bf996fa51b0da953b7d1"
ALTER INDEX "certifyscorecard_source_id_origin_collector_scorecard_version_s" RENAME TO "certifyscorecard_source_id_ori_508fb6b816b5bf996fa51b0da953b7d1";
-- Rename an index from "certifyvuln_package_id_vulnerability_id_collector_scanner_uri_s" to "certifyvuln_package_id_vulnera_77eeb86290f40a475550cafdc6ff7168"
ALTER INDEX "certifyvuln_package_id_vulnerability_id_collector_scanner_uri_s" RENAME TO "certifyvuln_package_id_vulnera_77eeb86290f40a475550cafdc6ff7168";
-- Rename an index from "hassourceat_source_id_package_name_id_justification_origin_coll" to "hassourceat_source_id_package__568bc11d70ea247e8b9260aa5f8db55d"
ALTER INDEX "hassourceat_source_id_package_name_id_justification_origin_coll" RENAME TO "hassourceat_source_id_package__568bc11d70ea247e8b9260aa5f8db55d";
-- Rename an index from "hassourceat_source_id_package_version_id_justification_origin_c" to "hassourceat_source_id_package__3f3922781897bf9d4f13a387d2ee1087"
ALTER INDEX "hassourceat_source_id_package_version_id_justification_origin_c" RENAME TO "hassourceat_source_id_package__3f3922781897bf9d4f13a387d2ee1087";
-- Rename an index from "hashequal_art_id_equal_art_id_artifacts_hash_origin_justificati" to "hashequal_art_id_equal_art_id__b59aed1c2db16430ebb5ff1773c11d79"
ALTER INDEX "hashequal_art_id_equal_art_id_artifacts_hash_origin_justificati" RENAME TO "hashequal_art_id_equal_art_id__b59aed1c2db16430ebb5ff1773c11d79";
-- Rename an index from "pkgequal_pkg_id_equal_pkg_id_packages_hash_origin_justification" to "pkgequal_pkg_id_equal_pkg_id_p_f643240e18bf980c4dcfa27572edf71a"
ALTER INDEX "pkgequal_pkg_id_equal_pkg_id_packages_hash_origin_justification" RENAME TO "pkgequal_pkg_id_equal_pkg_id_p_f643240e18bf980c4dcfa27572edf71a";
-- Rename an index from "slsaattestation_subject_id_origin_collector_document_ref_build_" to "slsaattestation_subject_id_ori_c12d4f9a94b2524558ac44ae3d65a07c"
ALTER INDEX "slsaattestation_subject_id_origin_collector_document_ref_build_" RENAME TO "slsaattestation_subject_id_ori_c12d4f9a94b2524558ac44ae3d65a07c";
-- Rename an index from "vulnequal_vuln_id_equal_vuln_id_vulnerabilities_hash_justificat" to "vulnequal_vuln_id_equal_vuln_i_67baeaab87be2e7cbf2595bd0c907077"
ALTER INDEX "vulnequal_vuln_id_equal_vuln_id_vulnerabilities_hash_justificat" RENAME TO "vulnequal_vuln_id_equal_vuln_i_67baeaab87be2e7cbf2595bd0c907077";
-- Rename an index from "vulnerabilitymetadata_vulnerability_id_id_score_type_score_valu" to "vulnerabilitymetadata_vulnerab_925c5bef552e5cc97592b157d457801a"
ALTER INDEX "vulnerabilitymetadata_vulnerability_id_id_score_type_score_valu" RENAME TO "vulnerabilitymetadata_vulnerab_925c5bef552e5cc97592b157d457801a";
-- Modify "bill_of_materials_included_software_artifacts" table
ALTER TABLE "bill_of_materials_included_software_artifacts" DROP CONSTRAINT "bill_of_materials_included_software_artifacts_bill_of_materials", ADD CONSTRAINT "bill_of_materials_included_sof_e0f27da27586c6a2e5283387e23a78a9" FOREIGN KEY ("bill_of_materials_id") REFERENCES "bill_of_materials" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;
-- Modify "bill_of_materials_included_software_packages" table
ALTER TABLE "bill_of_materials_included_software_packages" DROP CONSTRAINT "bill_of_materials_included_software_packages_bill_of_materials_", ADD CONSTRAINT "bill_of_materials_included_sof_e693ffa2b7282443b21e5364ba12390a" FOREIGN KEY ("bill_of_materials_id") REFERENCES "bill_of_materials" ("id") ON UPDATE NO ACTION ON DELETE CASCADE;
