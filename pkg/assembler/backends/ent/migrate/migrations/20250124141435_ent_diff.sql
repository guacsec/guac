-- Drop index "license_name_inline_list_version" from table: "licenses"
DROP INDEX "license_name_inline_list_version";
-- Modify "licenses" table
ALTER TABLE "licenses" ADD COLUMN "inline_hash" character varying NULL, ADD COLUMN "list_version_hash" character varying NULL;
-- Update the new column with the SHA1 hash of the existing field using PostgreSQL's digest function
UPDATE "licenses"
SET "inline_hash" = encode(digest("inline", 'sha1'), 'hex');
UPDATE "licenses"
SET "list_version_hash" = encode(digest("list_version", 'sha1'), 'hex');
-- Create index "license_name_inline_hash_list_version_hash" to table: "licenses"
CREATE UNIQUE INDEX "license_name_inline_hash_list_version_hash" ON "licenses" ("name", "inline_hash", "list_version_hash");
