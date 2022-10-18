CREATE TABLE roles
(
    id              BIGSERIAL NOT NULL PRIMARY KEY,
    id_organization BIGINT    NOT NULL REFERENCES organizations (id),
    role_name       VARCHAR(255),
    permission      VARCHAR(255),
    created_at      TIMESTAMP WITHOUT TIME ZONE,
    updated_at      TIMESTAMP WITHOUT TIME ZONE
);
