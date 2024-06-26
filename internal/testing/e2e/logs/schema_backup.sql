--
-- PostgreSQL database dump
--

-- Dumped from database version 16.3 (Debian 16.3-1.pgdg120+1)
-- Dumped by pg_dump version 16.3 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: artifacts; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.artifacts (
    id uuid NOT NULL,
    algorithm character varying NOT NULL,
    digest character varying NOT NULL
);


ALTER TABLE public.artifacts OWNER TO guac;

--
-- Name: bill_of_materials; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.bill_of_materials (
    id uuid NOT NULL,
    uri character varying NOT NULL,
    algorithm character varying NOT NULL,
    digest character varying NOT NULL,
    download_location character varying NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    known_since timestamp with time zone NOT NULL,
    included_packages_hash character varying NOT NULL,
    included_artifacts_hash character varying NOT NULL,
    included_dependencies_hash character varying NOT NULL,
    included_occurrences_hash character varying NOT NULL,
    package_id uuid,
    artifact_id uuid
);


ALTER TABLE public.bill_of_materials OWNER TO guac;

--
-- Name: bill_of_materials_included_dependencies; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.bill_of_materials_included_dependencies (
    bill_of_materials_id uuid NOT NULL,
    dependency_id uuid NOT NULL
);


ALTER TABLE public.bill_of_materials_included_dependencies OWNER TO guac;

--
-- Name: bill_of_materials_included_occurrences; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.bill_of_materials_included_occurrences (
    bill_of_materials_id uuid NOT NULL,
    occurrence_id uuid NOT NULL
);


ALTER TABLE public.bill_of_materials_included_occurrences OWNER TO guac;

--
-- Name: bill_of_materials_included_software_artifacts; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.bill_of_materials_included_software_artifacts (
    bill_of_materials_id uuid NOT NULL,
    artifact_id uuid NOT NULL
);


ALTER TABLE public.bill_of_materials_included_software_artifacts OWNER TO guac;

--
-- Name: bill_of_materials_included_software_packages; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.bill_of_materials_included_software_packages (
    bill_of_materials_id uuid NOT NULL,
    package_version_id uuid NOT NULL
);


ALTER TABLE public.bill_of_materials_included_software_packages OWNER TO guac;

--
-- Name: builders; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.builders (
    id uuid NOT NULL,
    uri character varying NOT NULL
);


ALTER TABLE public.builders OWNER TO guac;

--
-- Name: certifications; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.certifications (
    id uuid NOT NULL,
    type character varying DEFAULT 'GOOD'::character varying NOT NULL,
    justification character varying NOT NULL,
    known_since timestamp with time zone NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    source_id uuid,
    package_version_id uuid,
    package_name_id uuid,
    artifact_id uuid
);


ALTER TABLE public.certifications OWNER TO guac;

--
-- Name: certify_legal_declared_licenses; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.certify_legal_declared_licenses (
    certify_legal_id uuid NOT NULL,
    license_id uuid NOT NULL
);


ALTER TABLE public.certify_legal_declared_licenses OWNER TO guac;

--
-- Name: certify_legal_discovered_licenses; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.certify_legal_discovered_licenses (
    certify_legal_id uuid NOT NULL,
    license_id uuid NOT NULL
);


ALTER TABLE public.certify_legal_discovered_licenses OWNER TO guac;

--
-- Name: certify_legals; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.certify_legals (
    id uuid NOT NULL,
    declared_license character varying NOT NULL,
    discovered_license character varying NOT NULL,
    attribution character varying NOT NULL,
    justification character varying NOT NULL,
    time_scanned timestamp with time zone NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    declared_licenses_hash character varying NOT NULL,
    discovered_licenses_hash character varying NOT NULL,
    package_id uuid,
    source_id uuid
);


ALTER TABLE public.certify_legals OWNER TO guac;

--
-- Name: certify_scorecards; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.certify_scorecards (
    id uuid NOT NULL,
    checks jsonb NOT NULL,
    aggregate_score double precision DEFAULT 0 NOT NULL,
    time_scanned timestamp with time zone NOT NULL,
    scorecard_version character varying NOT NULL,
    scorecard_commit character varying NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    checks_hash character varying NOT NULL,
    source_id uuid NOT NULL
);


ALTER TABLE public.certify_scorecards OWNER TO guac;

--
-- Name: certify_vexes; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.certify_vexes (
    id uuid NOT NULL,
    known_since timestamp with time zone NOT NULL,
    status character varying NOT NULL,
    statement character varying NOT NULL,
    status_notes character varying NOT NULL,
    justification character varying NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    package_id uuid,
    artifact_id uuid,
    vulnerability_id uuid NOT NULL
);


ALTER TABLE public.certify_vexes OWNER TO guac;

--
-- Name: certify_vulns; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.certify_vulns (
    id uuid NOT NULL,
    time_scanned timestamp with time zone NOT NULL,
    db_uri character varying NOT NULL,
    db_version character varying NOT NULL,
    scanner_uri character varying NOT NULL,
    scanner_version character varying NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    vulnerability_id uuid NOT NULL,
    package_id uuid NOT NULL
);


ALTER TABLE public.certify_vulns OWNER TO guac;

--
-- Name: dependencies; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.dependencies (
    id uuid NOT NULL,
    version_range character varying NOT NULL,
    dependency_type character varying NOT NULL,
    justification character varying NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    package_id uuid NOT NULL,
    dependent_package_name_id uuid,
    dependent_package_version_id uuid
);


ALTER TABLE public.dependencies OWNER TO guac;

--
-- Name: ent_types; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.ent_types (
    id bigint NOT NULL,
    type character varying NOT NULL
);


ALTER TABLE public.ent_types OWNER TO guac;

--
-- Name: ent_types_id_seq; Type: SEQUENCE; Schema: public; Owner: guac
--

ALTER TABLE public.ent_types ALTER COLUMN id ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME public.ent_types_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: has_metadata; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.has_metadata (
    id uuid NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    key character varying NOT NULL,
    value character varying NOT NULL,
    justification character varying NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    source_id uuid,
    package_version_id uuid,
    package_name_id uuid,
    artifact_id uuid
);


ALTER TABLE public.has_metadata OWNER TO guac;

--
-- Name: has_source_ats; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.has_source_ats (
    id uuid NOT NULL,
    known_since timestamp with time zone NOT NULL,
    justification character varying NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    package_version_id uuid,
    package_name_id uuid,
    source_id uuid NOT NULL
);


ALTER TABLE public.has_source_ats OWNER TO guac;

--
-- Name: hash_equals; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.hash_equals (
    id uuid NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    justification character varying NOT NULL,
    document_ref character varying NOT NULL,
    artifacts_hash character varying NOT NULL,
    art_id uuid NOT NULL,
    equal_art_id uuid NOT NULL
);


ALTER TABLE public.hash_equals OWNER TO guac;

--
-- Name: licenses; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.licenses (
    id uuid NOT NULL,
    name character varying NOT NULL,
    inline character varying,
    list_version character varying
);


ALTER TABLE public.licenses OWNER TO guac;

--
-- Name: occurrences; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.occurrences (
    id uuid NOT NULL,
    justification character varying NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    artifact_id uuid NOT NULL,
    package_id uuid,
    source_id uuid
);


ALTER TABLE public.occurrences OWNER TO guac;

--
-- Name: package_names; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.package_names (
    id uuid NOT NULL,
    type character varying NOT NULL,
    namespace character varying NOT NULL,
    name character varying NOT NULL
);


ALTER TABLE public.package_names OWNER TO guac;

--
-- Name: package_versions; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.package_versions (
    id uuid NOT NULL,
    version character varying DEFAULT ''::character varying NOT NULL,
    subpath character varying DEFAULT ''::character varying NOT NULL,
    qualifiers jsonb,
    hash character varying NOT NULL,
    name_id uuid NOT NULL
);


ALTER TABLE public.package_versions OWNER TO guac;

--
-- Name: pkg_equals; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.pkg_equals (
    id uuid NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    justification character varying NOT NULL,
    packages_hash character varying NOT NULL,
    pkg_id uuid NOT NULL,
    equal_pkg_id uuid NOT NULL
);


ALTER TABLE public.pkg_equals OWNER TO guac;

--
-- Name: point_of_contacts; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.point_of_contacts (
    id uuid NOT NULL,
    email character varying NOT NULL,
    info character varying NOT NULL,
    since timestamp with time zone NOT NULL,
    justification character varying NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    source_id uuid,
    package_version_id uuid,
    package_name_id uuid,
    artifact_id uuid
);


ALTER TABLE public.point_of_contacts OWNER TO guac;

--
-- Name: slsa_attestation_built_from; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.slsa_attestation_built_from (
    slsa_attestation_id uuid NOT NULL,
    artifact_id uuid NOT NULL
);


ALTER TABLE public.slsa_attestation_built_from OWNER TO guac;

--
-- Name: slsa_attestations; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.slsa_attestations (
    id uuid NOT NULL,
    build_type character varying NOT NULL,
    slsa_predicate jsonb,
    slsa_version character varying NOT NULL,
    started_on timestamp with time zone NOT NULL,
    finished_on timestamp with time zone NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    built_from_hash character varying NOT NULL,
    built_by_id uuid NOT NULL,
    subject_id uuid NOT NULL
);


ALTER TABLE public.slsa_attestations OWNER TO guac;

--
-- Name: source_names; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.source_names (
    id uuid NOT NULL,
    type character varying NOT NULL,
    namespace character varying NOT NULL,
    name character varying NOT NULL,
    commit character varying,
    tag character varying
);


ALTER TABLE public.source_names OWNER TO guac;

--
-- Name: vuln_equals; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.vuln_equals (
    id uuid NOT NULL,
    justification character varying NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    vulnerabilities_hash character varying NOT NULL,
    vuln_id uuid NOT NULL,
    equal_vuln_id uuid NOT NULL
);


ALTER TABLE public.vuln_equals OWNER TO guac;

--
-- Name: vulnerability_ids; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.vulnerability_ids (
    id uuid NOT NULL,
    vulnerability_id character varying NOT NULL,
    type character varying NOT NULL
);


ALTER TABLE public.vulnerability_ids OWNER TO guac;

--
-- Name: vulnerability_metadata; Type: TABLE; Schema: public; Owner: guac
--

CREATE TABLE public.vulnerability_metadata (
    id uuid NOT NULL,
    score_type character varying NOT NULL,
    score_value double precision NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    origin character varying NOT NULL,
    collector character varying NOT NULL,
    document_ref character varying NOT NULL,
    vulnerability_id_id uuid NOT NULL
);


ALTER TABLE public.vulnerability_metadata OWNER TO guac;

--
-- Name: artifacts artifacts_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.artifacts
    ADD CONSTRAINT artifacts_pkey PRIMARY KEY (id);


--
-- Name: bill_of_materials_included_dependencies bill_of_materials_included_dependencies_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials_included_dependencies
    ADD CONSTRAINT bill_of_materials_included_dependencies_pkey PRIMARY KEY (bill_of_materials_id, dependency_id);


--
-- Name: bill_of_materials_included_occurrences bill_of_materials_included_occurrences_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials_included_occurrences
    ADD CONSTRAINT bill_of_materials_included_occurrences_pkey PRIMARY KEY (bill_of_materials_id, occurrence_id);


--
-- Name: bill_of_materials_included_software_artifacts bill_of_materials_included_software_artifacts_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials_included_software_artifacts
    ADD CONSTRAINT bill_of_materials_included_software_artifacts_pkey PRIMARY KEY (bill_of_materials_id, artifact_id);


--
-- Name: bill_of_materials_included_software_packages bill_of_materials_included_software_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials_included_software_packages
    ADD CONSTRAINT bill_of_materials_included_software_packages_pkey PRIMARY KEY (bill_of_materials_id, package_version_id);


--
-- Name: bill_of_materials bill_of_materials_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials
    ADD CONSTRAINT bill_of_materials_pkey PRIMARY KEY (id);


--
-- Name: builders builders_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.builders
    ADD CONSTRAINT builders_pkey PRIMARY KEY (id);


--
-- Name: certifications certifications_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certifications
    ADD CONSTRAINT certifications_pkey PRIMARY KEY (id);


--
-- Name: certify_legal_declared_licenses certify_legal_declared_licenses_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_legal_declared_licenses
    ADD CONSTRAINT certify_legal_declared_licenses_pkey PRIMARY KEY (certify_legal_id, license_id);


--
-- Name: certify_legal_discovered_licenses certify_legal_discovered_licenses_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_legal_discovered_licenses
    ADD CONSTRAINT certify_legal_discovered_licenses_pkey PRIMARY KEY (certify_legal_id, license_id);


--
-- Name: certify_legals certify_legals_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_legals
    ADD CONSTRAINT certify_legals_pkey PRIMARY KEY (id);


--
-- Name: certify_scorecards certify_scorecards_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_scorecards
    ADD CONSTRAINT certify_scorecards_pkey PRIMARY KEY (id);


--
-- Name: certify_vexes certify_vexes_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_vexes
    ADD CONSTRAINT certify_vexes_pkey PRIMARY KEY (id);


--
-- Name: certify_vulns certify_vulns_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_vulns
    ADD CONSTRAINT certify_vulns_pkey PRIMARY KEY (id);


--
-- Name: dependencies dependencies_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.dependencies
    ADD CONSTRAINT dependencies_pkey PRIMARY KEY (id);


--
-- Name: ent_types ent_types_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.ent_types
    ADD CONSTRAINT ent_types_pkey PRIMARY KEY (id);


--
-- Name: has_metadata has_metadata_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.has_metadata
    ADD CONSTRAINT has_metadata_pkey PRIMARY KEY (id);


--
-- Name: has_source_ats has_source_ats_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.has_source_ats
    ADD CONSTRAINT has_source_ats_pkey PRIMARY KEY (id);


--
-- Name: hash_equals hash_equals_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.hash_equals
    ADD CONSTRAINT hash_equals_pkey PRIMARY KEY (id);


--
-- Name: licenses licenses_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.licenses
    ADD CONSTRAINT licenses_pkey PRIMARY KEY (id);


--
-- Name: occurrences occurrences_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.occurrences
    ADD CONSTRAINT occurrences_pkey PRIMARY KEY (id);


--
-- Name: package_names package_names_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.package_names
    ADD CONSTRAINT package_names_pkey PRIMARY KEY (id);


--
-- Name: package_versions package_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.package_versions
    ADD CONSTRAINT package_versions_pkey PRIMARY KEY (id);


--
-- Name: pkg_equals pkg_equals_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.pkg_equals
    ADD CONSTRAINT pkg_equals_pkey PRIMARY KEY (id);


--
-- Name: point_of_contacts point_of_contacts_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.point_of_contacts
    ADD CONSTRAINT point_of_contacts_pkey PRIMARY KEY (id);


--
-- Name: slsa_attestation_built_from slsa_attestation_built_from_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.slsa_attestation_built_from
    ADD CONSTRAINT slsa_attestation_built_from_pkey PRIMARY KEY (slsa_attestation_id, artifact_id);


--
-- Name: slsa_attestations slsa_attestations_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.slsa_attestations
    ADD CONSTRAINT slsa_attestations_pkey PRIMARY KEY (id);


--
-- Name: source_names source_names_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.source_names
    ADD CONSTRAINT source_names_pkey PRIMARY KEY (id);


--
-- Name: vuln_equals vuln_equals_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.vuln_equals
    ADD CONSTRAINT vuln_equals_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_ids vulnerability_ids_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.vulnerability_ids
    ADD CONSTRAINT vulnerability_ids_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_metadata vulnerability_metadata_pkey; Type: CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.vulnerability_metadata
    ADD CONSTRAINT vulnerability_metadata_pkey PRIMARY KEY (id);


--
-- Name: artifact_algorithm_digest; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX artifact_algorithm_digest ON public.artifacts USING btree (algorithm, digest);


--
-- Name: builder_uri; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX builder_uri ON public.builders USING btree (uri);


--
-- Name: builders_uri_key; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX builders_uri_key ON public.builders USING btree (uri);


--
-- Name: certification_type_justificati_050322ac123e59b56b741a07ea26df53; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX certification_type_justificati_050322ac123e59b56b741a07ea26df53 ON public.certifications USING btree (type, justification, origin, collector, package_name_id, known_since, document_ref) WHERE ((source_id IS NULL) AND (package_version_id IS NULL) AND (package_name_id IS NOT NULL) AND (artifact_id IS NULL));


--
-- Name: certification_type_justificati_a82272635ecbc67a1e08d7bed937351b; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX certification_type_justificati_a82272635ecbc67a1e08d7bed937351b ON public.certifications USING btree (type, justification, origin, collector, source_id, known_since, document_ref) WHERE ((source_id IS NOT NULL) AND (package_version_id IS NULL) AND (package_name_id IS NULL) AND (artifact_id IS NULL));


--
-- Name: certification_type_justificati_c6d282e2f14094c4106b3d2b0ac979f4; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX certification_type_justificati_c6d282e2f14094c4106b3d2b0ac979f4 ON public.certifications USING btree (type, justification, origin, collector, package_version_id, known_since, document_ref) WHERE ((source_id IS NULL) AND (package_version_id IS NOT NULL) AND (package_name_id IS NULL) AND (artifact_id IS NULL));


--
-- Name: certification_type_justificati_e71e1f69147e5d0ef7f614cb12b42373; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX certification_type_justificati_e71e1f69147e5d0ef7f614cb12b42373 ON public.certifications USING btree (type, justification, origin, collector, artifact_id, known_since, document_ref) WHERE ((source_id IS NULL) AND (package_version_id IS NULL) AND (package_name_id IS NULL) AND (artifact_id IS NOT NULL));


--
-- Name: certifylegal_package_id_declar_37fd118fe84f0a1eb9042a047d066a77; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX certifylegal_package_id_declar_37fd118fe84f0a1eb9042a047d066a77 ON public.certify_legals USING btree (package_id, declared_license, discovered_license, attribution, justification, time_scanned, origin, collector, document_ref, declared_licenses_hash, discovered_licenses_hash) WHERE ((package_id IS NOT NULL) AND (source_id IS NULL));


--
-- Name: certifylegal_source_id_declare_7172c32e012f5a3f84156bd57473bcd2; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX certifylegal_source_id_declare_7172c32e012f5a3f84156bd57473bcd2 ON public.certify_legals USING btree (source_id, declared_license, discovered_license, attribution, justification, time_scanned, origin, collector, document_ref, declared_licenses_hash, discovered_licenses_hash) WHERE ((package_id IS NULL) AND (source_id IS NOT NULL));


--
-- Name: certifyscorecard_source_id_ori_508fb6b816b5bf996fa51b0da953b7d1; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX certifyscorecard_source_id_ori_508fb6b816b5bf996fa51b0da953b7d1 ON public.certify_scorecards USING btree (source_id, origin, collector, scorecard_version, scorecard_commit, aggregate_score, time_scanned, checks_hash, document_ref);


--
-- Name: certifyvuln_db_uri_db_version__21c35a4e5f38654fa77920fb7bbb325c; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX certifyvuln_db_uri_db_version__21c35a4e5f38654fa77920fb7bbb325c ON public.certify_vulns USING btree (db_uri, db_version, scanner_uri, scanner_version, origin, collector, time_scanned, document_ref, vulnerability_id, package_id);


--
-- Name: dep_package_name_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX dep_package_name_id ON public.dependencies USING btree (version_range, dependency_type, justification, origin, collector, document_ref, package_id, dependent_package_name_id) WHERE ((dependent_package_name_id IS NOT NULL) AND (dependent_package_version_id IS NULL));


--
-- Name: dep_package_version_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX dep_package_version_id ON public.dependencies USING btree (version_range, dependency_type, justification, origin, collector, document_ref, package_id, dependent_package_version_id) WHERE ((dependent_package_name_id IS NULL) AND (dependent_package_version_id IS NOT NULL));


--
-- Name: ent_types_type_key; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX ent_types_type_key ON public.ent_types USING btree (type);


--
-- Name: has_metadata_artifact_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX has_metadata_artifact_id ON public.has_metadata USING btree (key, value, justification, origin, collector, "timestamp", document_ref, artifact_id) WHERE ((source_id IS NULL) AND (package_version_id IS NULL) AND (package_name_id IS NULL) AND (artifact_id IS NOT NULL));


--
-- Name: has_metadata_package_name_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX has_metadata_package_name_id ON public.has_metadata USING btree (key, value, justification, origin, collector, "timestamp", document_ref, package_name_id) WHERE ((source_id IS NULL) AND (package_version_id IS NULL) AND (package_name_id IS NOT NULL) AND (artifact_id IS NULL));


--
-- Name: has_metadata_package_version_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX has_metadata_package_version_id ON public.has_metadata USING btree (key, value, justification, origin, collector, "timestamp", document_ref, package_version_id) WHERE ((source_id IS NULL) AND (package_version_id IS NOT NULL) AND (package_name_id IS NULL) AND (artifact_id IS NULL));


--
-- Name: has_metadata_source_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX has_metadata_source_id ON public.has_metadata USING btree (key, value, justification, origin, collector, "timestamp", document_ref, source_id) WHERE ((source_id IS NOT NULL) AND (package_version_id IS NULL) AND (package_name_id IS NULL) AND (artifact_id IS NULL));


--
-- Name: hashequal_art_id_equal_art_id__b59aed1c2db16430ebb5ff1773c11d79; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX hashequal_art_id_equal_art_id__b59aed1c2db16430ebb5ff1773c11d79 ON public.hash_equals USING btree (art_id, equal_art_id, artifacts_hash, origin, justification, collector, document_ref);


--
-- Name: hassourceat_source_id_package__3f3922781897bf9d4f13a387d2ee1087; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX hassourceat_source_id_package__3f3922781897bf9d4f13a387d2ee1087 ON public.has_source_ats USING btree (source_id, package_version_id, justification, origin, collector, known_since, document_ref) WHERE ((package_version_id IS NOT NULL) AND (package_name_id IS NULL));


--
-- Name: hassourceat_source_id_package__568bc11d70ea247e8b9260aa5f8db55d; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX hassourceat_source_id_package__568bc11d70ea247e8b9260aa5f8db55d ON public.has_source_ats USING btree (source_id, package_name_id, justification, origin, collector, known_since, document_ref) WHERE ((package_name_id IS NOT NULL) AND (package_version_id IS NULL));


--
-- Name: license_name_inline_list_version; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX license_name_inline_list_version ON public.licenses USING btree (name, inline, list_version);


--
-- Name: occurrence_package_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX occurrence_package_id ON public.occurrences USING btree (justification, origin, collector, document_ref, artifact_id, package_id) WHERE ((package_id IS NOT NULL) AND (source_id IS NULL));


--
-- Name: occurrence_source_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX occurrence_source_id ON public.occurrences USING btree (justification, origin, collector, document_ref, artifact_id, source_id) WHERE ((package_id IS NULL) AND (source_id IS NOT NULL));


--
-- Name: packagename_name_namespace_type; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX packagename_name_namespace_type ON public.package_names USING btree (name, namespace, type);


--
-- Name: packageversion_hash_name_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX packageversion_hash_name_id ON public.package_versions USING btree (hash, name_id);


--
-- Name: packageversion_qualifiers; Type: INDEX; Schema: public; Owner: guac
--

CREATE INDEX packageversion_qualifiers ON public.package_versions USING gin (qualifiers);


--
-- Name: packageversion_version_subpath_qualifiers_name_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX packageversion_version_subpath_qualifiers_name_id ON public.package_versions USING btree (version, subpath, qualifiers, name_id);


--
-- Name: pkgequal_pkg_id_equal_pkg_id_p_f643240e18bf980c4dcfa27572edf71a; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX pkgequal_pkg_id_equal_pkg_id_p_f643240e18bf980c4dcfa27572edf71a ON public.pkg_equals USING btree (pkg_id, equal_pkg_id, packages_hash, origin, justification, collector, document_ref);


--
-- Name: poc_artifact_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX poc_artifact_id ON public.point_of_contacts USING btree (since, email, info, justification, origin, collector, document_ref, artifact_id) WHERE ((source_id IS NULL) AND (package_version_id IS NULL) AND (package_name_id IS NULL) AND (artifact_id IS NOT NULL));


--
-- Name: poc_package_name_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX poc_package_name_id ON public.point_of_contacts USING btree (since, email, info, justification, origin, collector, document_ref, package_name_id) WHERE ((source_id IS NULL) AND (package_version_id IS NULL) AND (package_name_id IS NOT NULL) AND (artifact_id IS NULL));


--
-- Name: poc_package_version_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX poc_package_version_id ON public.point_of_contacts USING btree (since, email, info, justification, origin, collector, document_ref, package_version_id) WHERE ((source_id IS NULL) AND (package_version_id IS NOT NULL) AND (package_name_id IS NULL) AND (artifact_id IS NULL));


--
-- Name: poc_source_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX poc_source_id ON public.point_of_contacts USING btree (since, email, info, justification, origin, collector, document_ref, source_id) WHERE ((source_id IS NOT NULL) AND (package_version_id IS NULL) AND (package_name_id IS NULL) AND (artifact_id IS NULL));


--
-- Name: sbom_artifact_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX sbom_artifact_id ON public.bill_of_materials USING btree (algorithm, digest, uri, download_location, known_since, included_packages_hash, included_artifacts_hash, included_dependencies_hash, included_occurrences_hash, origin, collector, document_ref, artifact_id) WHERE ((package_id IS NULL) AND (artifact_id IS NOT NULL));


--
-- Name: sbom_package_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX sbom_package_id ON public.bill_of_materials USING btree (algorithm, digest, uri, download_location, known_since, included_packages_hash, included_artifacts_hash, included_dependencies_hash, included_occurrences_hash, origin, collector, document_ref, package_id) WHERE ((package_id IS NOT NULL) AND (artifact_id IS NULL));


--
-- Name: slsaattestation_subject_id_ori_c12d4f9a94b2524558ac44ae3d65a07c; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX slsaattestation_subject_id_ori_c12d4f9a94b2524558ac44ae3d65a07c ON public.slsa_attestations USING btree (subject_id, origin, collector, document_ref, build_type, slsa_version, built_by_id, built_from_hash, started_on, finished_on);


--
-- Name: sourcename_type_namespace_name_commit_tag; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX sourcename_type_namespace_name_commit_tag ON public.source_names USING btree (type, namespace, name, commit, tag);


--
-- Name: vex_artifact_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX vex_artifact_id ON public.certify_vexes USING btree (known_since, justification, status, statement, status_notes, origin, collector, document_ref, vulnerability_id, package_id) WHERE (artifact_id IS NULL);


--
-- Name: vex_package_id; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX vex_package_id ON public.certify_vexes USING btree (known_since, justification, status, statement, status_notes, origin, collector, document_ref, vulnerability_id, artifact_id) WHERE (package_id IS NULL);


--
-- Name: vulnequal_vuln_id_equal_vuln_i_67baeaab87be2e7cbf2595bd0c907077; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX vulnequal_vuln_id_equal_vuln_i_67baeaab87be2e7cbf2595bd0c907077 ON public.vuln_equals USING btree (vuln_id, equal_vuln_id, vulnerabilities_hash, justification, origin, collector, document_ref);


--
-- Name: vulnerabilityid_vulnerability_id_type; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX vulnerabilityid_vulnerability_id_type ON public.vulnerability_ids USING btree (vulnerability_id, type);


--
-- Name: vulnerabilitymetadata_vulnerab_925c5bef552e5cc97592b157d457801a; Type: INDEX; Schema: public; Owner: guac
--

CREATE UNIQUE INDEX vulnerabilitymetadata_vulnerab_925c5bef552e5cc97592b157d457801a ON public.vulnerability_metadata USING btree (vulnerability_id_id, score_type, score_value, "timestamp", origin, collector, document_ref);


--
-- Name: bill_of_materials bill_of_materials_artifacts_artifact; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials
    ADD CONSTRAINT bill_of_materials_artifacts_artifact FOREIGN KEY (artifact_id) REFERENCES public.artifacts(id) ON DELETE SET NULL;


--
-- Name: bill_of_materials_included_dependencies bill_of_materials_included_dependencies_bill_of_materials_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials_included_dependencies
    ADD CONSTRAINT bill_of_materials_included_dependencies_bill_of_materials_id FOREIGN KEY (bill_of_materials_id) REFERENCES public.bill_of_materials(id) ON DELETE CASCADE;


--
-- Name: bill_of_materials_included_dependencies bill_of_materials_included_dependencies_dependency_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials_included_dependencies
    ADD CONSTRAINT bill_of_materials_included_dependencies_dependency_id FOREIGN KEY (dependency_id) REFERENCES public.dependencies(id) ON DELETE CASCADE;


--
-- Name: bill_of_materials_included_occurrences bill_of_materials_included_occurrences_bill_of_materials_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials_included_occurrences
    ADD CONSTRAINT bill_of_materials_included_occurrences_bill_of_materials_id FOREIGN KEY (bill_of_materials_id) REFERENCES public.bill_of_materials(id) ON DELETE CASCADE;


--
-- Name: bill_of_materials_included_occurrences bill_of_materials_included_occurrences_occurrence_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials_included_occurrences
    ADD CONSTRAINT bill_of_materials_included_occurrences_occurrence_id FOREIGN KEY (occurrence_id) REFERENCES public.occurrences(id) ON DELETE CASCADE;


--
-- Name: bill_of_materials_included_software_artifacts bill_of_materials_included_sof_e0f27da27586c6a2e5283387e23a78a9; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials_included_software_artifacts
    ADD CONSTRAINT bill_of_materials_included_sof_e0f27da27586c6a2e5283387e23a78a9 FOREIGN KEY (bill_of_materials_id) REFERENCES public.bill_of_materials(id) ON DELETE CASCADE;


--
-- Name: bill_of_materials_included_software_packages bill_of_materials_included_sof_e693ffa2b7282443b21e5364ba12390a; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials_included_software_packages
    ADD CONSTRAINT bill_of_materials_included_sof_e693ffa2b7282443b21e5364ba12390a FOREIGN KEY (bill_of_materials_id) REFERENCES public.bill_of_materials(id) ON DELETE CASCADE;


--
-- Name: bill_of_materials_included_software_artifacts bill_of_materials_included_software_artifacts_artifact_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials_included_software_artifacts
    ADD CONSTRAINT bill_of_materials_included_software_artifacts_artifact_id FOREIGN KEY (artifact_id) REFERENCES public.artifacts(id) ON DELETE CASCADE;


--
-- Name: bill_of_materials_included_software_packages bill_of_materials_included_software_packages_package_version_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials_included_software_packages
    ADD CONSTRAINT bill_of_materials_included_software_packages_package_version_id FOREIGN KEY (package_version_id) REFERENCES public.package_versions(id) ON DELETE CASCADE;


--
-- Name: bill_of_materials bill_of_materials_package_versions_package; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.bill_of_materials
    ADD CONSTRAINT bill_of_materials_package_versions_package FOREIGN KEY (package_id) REFERENCES public.package_versions(id) ON DELETE SET NULL;


--
-- Name: certifications certifications_artifacts_artifact; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certifications
    ADD CONSTRAINT certifications_artifacts_artifact FOREIGN KEY (artifact_id) REFERENCES public.artifacts(id) ON DELETE SET NULL;


--
-- Name: certifications certifications_package_names_all_versions; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certifications
    ADD CONSTRAINT certifications_package_names_all_versions FOREIGN KEY (package_name_id) REFERENCES public.package_names(id) ON DELETE SET NULL;


--
-- Name: certifications certifications_package_versions_package_version; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certifications
    ADD CONSTRAINT certifications_package_versions_package_version FOREIGN KEY (package_version_id) REFERENCES public.package_versions(id) ON DELETE SET NULL;


--
-- Name: certifications certifications_source_names_source; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certifications
    ADD CONSTRAINT certifications_source_names_source FOREIGN KEY (source_id) REFERENCES public.source_names(id) ON DELETE SET NULL;


--
-- Name: certify_legal_declared_licenses certify_legal_declared_licenses_certify_legal_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_legal_declared_licenses
    ADD CONSTRAINT certify_legal_declared_licenses_certify_legal_id FOREIGN KEY (certify_legal_id) REFERENCES public.certify_legals(id) ON DELETE CASCADE;


--
-- Name: certify_legal_declared_licenses certify_legal_declared_licenses_license_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_legal_declared_licenses
    ADD CONSTRAINT certify_legal_declared_licenses_license_id FOREIGN KEY (license_id) REFERENCES public.licenses(id) ON DELETE CASCADE;


--
-- Name: certify_legal_discovered_licenses certify_legal_discovered_licenses_certify_legal_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_legal_discovered_licenses
    ADD CONSTRAINT certify_legal_discovered_licenses_certify_legal_id FOREIGN KEY (certify_legal_id) REFERENCES public.certify_legals(id) ON DELETE CASCADE;


--
-- Name: certify_legal_discovered_licenses certify_legal_discovered_licenses_license_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_legal_discovered_licenses
    ADD CONSTRAINT certify_legal_discovered_licenses_license_id FOREIGN KEY (license_id) REFERENCES public.licenses(id) ON DELETE CASCADE;


--
-- Name: certify_legals certify_legals_package_versions_package; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_legals
    ADD CONSTRAINT certify_legals_package_versions_package FOREIGN KEY (package_id) REFERENCES public.package_versions(id) ON DELETE SET NULL;


--
-- Name: certify_legals certify_legals_source_names_source; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_legals
    ADD CONSTRAINT certify_legals_source_names_source FOREIGN KEY (source_id) REFERENCES public.source_names(id) ON DELETE SET NULL;


--
-- Name: certify_scorecards certify_scorecards_source_names_source; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_scorecards
    ADD CONSTRAINT certify_scorecards_source_names_source FOREIGN KEY (source_id) REFERENCES public.source_names(id);


--
-- Name: certify_vexes certify_vexes_artifacts_artifact; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_vexes
    ADD CONSTRAINT certify_vexes_artifacts_artifact FOREIGN KEY (artifact_id) REFERENCES public.artifacts(id) ON DELETE SET NULL;


--
-- Name: certify_vexes certify_vexes_package_versions_package; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_vexes
    ADD CONSTRAINT certify_vexes_package_versions_package FOREIGN KEY (package_id) REFERENCES public.package_versions(id) ON DELETE SET NULL;


--
-- Name: certify_vexes certify_vexes_vulnerability_ids_vulnerability; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_vexes
    ADD CONSTRAINT certify_vexes_vulnerability_ids_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES public.vulnerability_ids(id);


--
-- Name: certify_vulns certify_vulns_package_versions_package; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_vulns
    ADD CONSTRAINT certify_vulns_package_versions_package FOREIGN KEY (package_id) REFERENCES public.package_versions(id);


--
-- Name: certify_vulns certify_vulns_vulnerability_ids_vulnerability; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.certify_vulns
    ADD CONSTRAINT certify_vulns_vulnerability_ids_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES public.vulnerability_ids(id);


--
-- Name: dependencies dependencies_package_names_dependent_package_name; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.dependencies
    ADD CONSTRAINT dependencies_package_names_dependent_package_name FOREIGN KEY (dependent_package_name_id) REFERENCES public.package_names(id) ON DELETE SET NULL;


--
-- Name: dependencies dependencies_package_versions_dependent_package_version; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.dependencies
    ADD CONSTRAINT dependencies_package_versions_dependent_package_version FOREIGN KEY (dependent_package_version_id) REFERENCES public.package_versions(id) ON DELETE SET NULL;


--
-- Name: dependencies dependencies_package_versions_package; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.dependencies
    ADD CONSTRAINT dependencies_package_versions_package FOREIGN KEY (package_id) REFERENCES public.package_versions(id);


--
-- Name: has_metadata has_metadata_artifacts_artifact; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.has_metadata
    ADD CONSTRAINT has_metadata_artifacts_artifact FOREIGN KEY (artifact_id) REFERENCES public.artifacts(id) ON DELETE SET NULL;


--
-- Name: has_metadata has_metadata_package_names_all_versions; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.has_metadata
    ADD CONSTRAINT has_metadata_package_names_all_versions FOREIGN KEY (package_name_id) REFERENCES public.package_names(id) ON DELETE SET NULL;


--
-- Name: has_metadata has_metadata_package_versions_package_version; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.has_metadata
    ADD CONSTRAINT has_metadata_package_versions_package_version FOREIGN KEY (package_version_id) REFERENCES public.package_versions(id) ON DELETE SET NULL;


--
-- Name: has_metadata has_metadata_source_names_source; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.has_metadata
    ADD CONSTRAINT has_metadata_source_names_source FOREIGN KEY (source_id) REFERENCES public.source_names(id) ON DELETE SET NULL;


--
-- Name: has_source_ats has_source_ats_package_names_all_versions; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.has_source_ats
    ADD CONSTRAINT has_source_ats_package_names_all_versions FOREIGN KEY (package_name_id) REFERENCES public.package_names(id) ON DELETE SET NULL;


--
-- Name: has_source_ats has_source_ats_package_versions_package_version; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.has_source_ats
    ADD CONSTRAINT has_source_ats_package_versions_package_version FOREIGN KEY (package_version_id) REFERENCES public.package_versions(id) ON DELETE SET NULL;


--
-- Name: has_source_ats has_source_ats_source_names_source; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.has_source_ats
    ADD CONSTRAINT has_source_ats_source_names_source FOREIGN KEY (source_id) REFERENCES public.source_names(id);


--
-- Name: hash_equals hash_equals_artifacts_artifact_a; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.hash_equals
    ADD CONSTRAINT hash_equals_artifacts_artifact_a FOREIGN KEY (art_id) REFERENCES public.artifacts(id);


--
-- Name: hash_equals hash_equals_artifacts_artifact_b; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.hash_equals
    ADD CONSTRAINT hash_equals_artifacts_artifact_b FOREIGN KEY (equal_art_id) REFERENCES public.artifacts(id);


--
-- Name: occurrences occurrences_artifacts_artifact; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.occurrences
    ADD CONSTRAINT occurrences_artifacts_artifact FOREIGN KEY (artifact_id) REFERENCES public.artifacts(id);


--
-- Name: occurrences occurrences_package_versions_package; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.occurrences
    ADD CONSTRAINT occurrences_package_versions_package FOREIGN KEY (package_id) REFERENCES public.package_versions(id) ON DELETE SET NULL;


--
-- Name: occurrences occurrences_source_names_source; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.occurrences
    ADD CONSTRAINT occurrences_source_names_source FOREIGN KEY (source_id) REFERENCES public.source_names(id) ON DELETE SET NULL;


--
-- Name: package_versions package_versions_package_names_versions; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.package_versions
    ADD CONSTRAINT package_versions_package_names_versions FOREIGN KEY (name_id) REFERENCES public.package_names(id) ON DELETE CASCADE;


--
-- Name: pkg_equals pkg_equals_package_versions_package_a; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.pkg_equals
    ADD CONSTRAINT pkg_equals_package_versions_package_a FOREIGN KEY (pkg_id) REFERENCES public.package_versions(id);


--
-- Name: pkg_equals pkg_equals_package_versions_package_b; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.pkg_equals
    ADD CONSTRAINT pkg_equals_package_versions_package_b FOREIGN KEY (equal_pkg_id) REFERENCES public.package_versions(id);


--
-- Name: point_of_contacts point_of_contacts_artifacts_artifact; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.point_of_contacts
    ADD CONSTRAINT point_of_contacts_artifacts_artifact FOREIGN KEY (artifact_id) REFERENCES public.artifacts(id) ON DELETE SET NULL;


--
-- Name: point_of_contacts point_of_contacts_package_names_all_versions; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.point_of_contacts
    ADD CONSTRAINT point_of_contacts_package_names_all_versions FOREIGN KEY (package_name_id) REFERENCES public.package_names(id) ON DELETE SET NULL;


--
-- Name: point_of_contacts point_of_contacts_package_versions_package_version; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.point_of_contacts
    ADD CONSTRAINT point_of_contacts_package_versions_package_version FOREIGN KEY (package_version_id) REFERENCES public.package_versions(id) ON DELETE SET NULL;


--
-- Name: point_of_contacts point_of_contacts_source_names_source; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.point_of_contacts
    ADD CONSTRAINT point_of_contacts_source_names_source FOREIGN KEY (source_id) REFERENCES public.source_names(id) ON DELETE SET NULL;


--
-- Name: slsa_attestation_built_from slsa_attestation_built_from_artifact_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.slsa_attestation_built_from
    ADD CONSTRAINT slsa_attestation_built_from_artifact_id FOREIGN KEY (artifact_id) REFERENCES public.artifacts(id) ON DELETE CASCADE;


--
-- Name: slsa_attestation_built_from slsa_attestation_built_from_slsa_attestation_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.slsa_attestation_built_from
    ADD CONSTRAINT slsa_attestation_built_from_slsa_attestation_id FOREIGN KEY (slsa_attestation_id) REFERENCES public.slsa_attestations(id) ON DELETE CASCADE;


--
-- Name: slsa_attestations slsa_attestations_artifacts_subject; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.slsa_attestations
    ADD CONSTRAINT slsa_attestations_artifacts_subject FOREIGN KEY (subject_id) REFERENCES public.artifacts(id);


--
-- Name: slsa_attestations slsa_attestations_builders_built_by; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.slsa_attestations
    ADD CONSTRAINT slsa_attestations_builders_built_by FOREIGN KEY (built_by_id) REFERENCES public.builders(id);


--
-- Name: vuln_equals vuln_equals_vulnerability_ids_vulnerability_a; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.vuln_equals
    ADD CONSTRAINT vuln_equals_vulnerability_ids_vulnerability_a FOREIGN KEY (vuln_id) REFERENCES public.vulnerability_ids(id);


--
-- Name: vuln_equals vuln_equals_vulnerability_ids_vulnerability_b; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.vuln_equals
    ADD CONSTRAINT vuln_equals_vulnerability_ids_vulnerability_b FOREIGN KEY (equal_vuln_id) REFERENCES public.vulnerability_ids(id);


--
-- Name: vulnerability_metadata vulnerability_metadata_vulnerability_ids_vulnerability_id; Type: FK CONSTRAINT; Schema: public; Owner: guac
--

ALTER TABLE ONLY public.vulnerability_metadata
    ADD CONSTRAINT vulnerability_metadata_vulnerability_ids_vulnerability_id FOREIGN KEY (vulnerability_id_id) REFERENCES public.vulnerability_ids(id);


--
-- PostgreSQL database dump complete
--

