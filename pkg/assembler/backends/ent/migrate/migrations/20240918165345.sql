-- Update the 'namespace' field if it contains 'guac-empty-@@'
UPDATE source_names
SET namespace = REPLACE(namespace, 'guac-empty-@@', '')
WHERE namespace LIKE '%guac-empty-@@%';

-- Update the 'tag' field if it contains 'guac-empty-@@'
UPDATE source_names
SET tag = REPLACE(tag, 'guac-empty-@@', '')
WHERE tag LIKE '%guac-empty-@@%';

-- Update the 'commit' field if it contains 'guac-empty-@@'
UPDATE source_names
SET commit = REPLACE(commit, 'guac-empty-@@', '')
WHERE commit LIKE '%guac-empty-@@%';

