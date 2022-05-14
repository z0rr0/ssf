DROP TABLE IF EXISTS `ssf`;
CREATE TABLE IF NOT EXISTS `ssf`
(
    `id`        VARCHAR(64) PRIMARY KEY,
    `file`      TEXT,
    `meta`      TEXT,
    `number`    INTEGER      NOT NULL DEFAULT 1,
    `salt_file` VARCHAR(256) NOT NULL,
    `salt_meta` VARCHAR(256) NOT NULL,
    `hash_file` VARCHAR(64)  NOT NULL,
    `hash_meta` VARCHAR(64)  NOT NULL,
    `created`   DATETIME     NOT NULL,
    `updated`   DATETIME     NOT NULL,
    `expired`   DATETIME     NOT NULL
);
CREATE INDEX IF NOT EXISTS `expired` ON `ssf` (`expired`, `number`);

/*
id - unique identifier UUID v4
file - relative path to an encrypted file
meta - encrypted file meta data, JSON {name, size, check sum}
number - usage file counter
salt_file - random salt for data
salt_meta - random salt for file name
hash_file - hash of file
hash_meta - hash of meta data
created - timestamp of item create
updated - timestamp of item update
expired - timestamp of item expiration
 */