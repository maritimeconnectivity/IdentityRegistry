CREATE TABLE logos
(
    id         BIGSERIAL NOT NULL PRIMARY KEY,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE,
    image      BYTEA     NOT NULL
);

CREATE TABLE organizations
(
    id                    BIGSERIAL     NOT NULL PRIMARY KEY,
    created_at            TIMESTAMP WITHOUT TIME ZONE,
    updated_at            TIMESTAMP WITHOUT TIME ZONE,
    name                  VARCHAR(255)  NOT NULL,
    mrn                   VARCHAR(255)  NOT NULL UNIQUE,
    mrn_subsidiary        VARCHAR(255) UNIQUE,
    home_mms_url          VARCHAR(255),
    email                 VARCHAR(255)  NOT NULL,
    url                   VARCHAR(512)  NOT NULL,
    address               VARCHAR(1000) NOT NULL,
    country               VARCHAR(64),
    approved              BOOLEAN       NOT NULL,
    federation_type       VARCHAR(255)  NOT NULL,
    id_logo               BIGINT,
    certificate_authority VARCHAR(255)  NOT NULL
);

CREATE TABLE devices
(
    id              BIGSERIAL    NOT NULL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    id_organization BIGINT       NOT NULL REFERENCES organizations (id),
    mrn             VARCHAR(255) NOT NULL UNIQUE,
    mrn_subsidiary  VARCHAR(255) UNIQUE,
    home_mms_url    VARCHAR(255),
    permissions     VARCHAR(4000),
    created_at      TIMESTAMP WITHOUT TIME ZONE,
    updated_at      TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE mmses
(
    id              BIGSERIAL    NOT NULL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    id_organization BIGINT       NOT NULL REFERENCES organizations (id),
    mrn             VARCHAR(255) NOT NULL UNIQUE,
    mrn_subsidiary  VARCHAR(255) UNIQUE,
    home_mms_url    VARCHAR(255),
    permissions     VARCHAR(255),
    created_at      TIMESTAMP WITHOUT TIME ZONE,
    updated_at      TIMESTAMP WITHOUT TIME ZONE,
    url             VARCHAR(255) NOT NULL
);

CREATE TABLE users
(
    id              BIGSERIAL    NOT NULL PRIMARY KEY,
    id_organization BIGINT       NOT NULL REFERENCES organizations (id),
    mrn             VARCHAR(255) NOT NULL UNIQUE,
    mrn_subsidiary  VARCHAR(255) UNIQUE,
    home_mms_url    VARCHAR(255),
    permissions     VARCHAR(255),
    created_at      TIMESTAMP WITHOUT TIME ZONE,
    updated_at      TIMESTAMP WITHOUT TIME ZONE,
    first_name      VARCHAR(255),
    last_name       VARCHAR(255),
    email           VARCHAR(255)
);

CREATE TABLE vessel_images
(
    id         BIGSERIAL NOT NULL PRIMARY KEY,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE,
    image      BYTEA     NOT NULL
);

CREATE TABLE vessels
(
    id              BIGSERIAL    NOT NULL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    id_organization BIGINT       NOT NULL REFERENCES organizations (id),
    mrn             VARCHAR(255) NOT NULL UNIQUE,
    mrn_subsidiary  VARCHAR(255) UNIQUE,
    home_mms_url    VARCHAR(255),
    permissions     VARCHAR(4000),
    created_at      TIMESTAMP WITHOUT TIME ZONE,
    updated_at      TIMESTAMP WITHOUT TIME ZONE,
    id_image        BIGINT REFERENCES vessel_images (id)
);

CREATE TABLE vessel_attributes
(
    id              BIGSERIAL    NOT NULL PRIMARY KEY,
    created_at      TIMESTAMP WITHOUT TIME ZONE,
    updated_at      TIMESTAMP WITHOUT TIME ZONE,
    attribute_name  VARCHAR(512) NOT NULL,
    attribute_value VARCHAR(512) NOT NULL,
    start           TIMESTAMP WITHOUT TIME ZONE,
    valid_until     TIMESTAMP WITHOUT TIME ZONE,
    id_vessel       BIGINT       NOT NULL REFERENCES vessels (id)
);

CREATE TABLE services
(
    id                 BIGSERIAL    NOT NULL PRIMARY KEY,
    name               VARCHAR(255) NOT NULL,
    id_organization    BIGINT       NOT NULL REFERENCES organizations (id),
    mrn                VARCHAR(255) NOT NULL,
    mrn_subsidiary     VARCHAR(255) UNIQUE,
    home_mms_url       VARCHAR(255),
    permissions        VARCHAR(4000),
    created_at         TIMESTAMP WITHOUT TIME ZONE,
    updated_at         TIMESTAMP WITHOUT TIME ZONE,
    oidc_access_type   VARCHAR(255),
    oidc_client_id     VARCHAR(255),
    oidc_client_secret VARCHAR(255),
    oidc_redirect_uri  VARCHAR(255),
    cert_domain_name   VARCHAR(255),
    instance_version   VARCHAR(255) NOT NULL,
    id_vessel          BIGINT REFERENCES vessels (id),
    UNIQUE (mrn, instance_version)
);

CREATE TABLE certificates
(
    id                    BIGSERIAL                   NOT NULL PRIMARY KEY,
    created_at            TIMESTAMP WITHOUT TIME ZONE,
    updated_at            TIMESTAMP WITHOUT TIME ZONE,
    certificate           TEXT                        NOT NULL,
    start                 TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    valid_until           TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    serial_number         NUMERIC(50)                 NOT NULL,
    revoked               BOOLEAN                     NOT NULL,
    revoked_at            TIMESTAMP WITHOUT TIME ZONE,
    revoke_reason         VARCHAR(64),
    certificate_authority VARCHAR(255)                NOT NULL,
    id_vessel             BIGINT REFERENCES vessels (id),
    id_user               BIGINT REFERENCES users (id),
    id_device             BIGINT REFERENCES devices (id),
    id_service            BIGINT REFERENCES services (id),
    id_mms                BIGINT REFERENCES mmses (id),
    id_organization       BIGINT REFERENCES organizations (id)
);

CREATE TABLE identity_provider_attributes
(
    id              BIGSERIAL     NOT NULL PRIMARY KEY,
    created_at      TIMESTAMP WITHOUT TIME ZONE,
    updated_at      TIMESTAMP WITHOUT TIME ZONE,
    attribute_name  VARCHAR(512)  NOT NULL,
    attribute_value VARCHAR(4000) NOT NULL,
    id_organization BIGINT        NOT NULL REFERENCES organizations (id)
);

CREATE TABLE acting_on_behalf
(
    id              BIGSERIAL NOT NULL PRIMARY KEY,
    created_at      TIMESTAMP WITHOUT TIME ZONE,
    updated_at      TIMESTAMP WITHOUT TIME ZONE,
    id_acting       BIGINT    NOT NULL REFERENCES organizations (id),
    id_on_behalf_of BIGINT    NOT NULL REFERENCES organizations (id)
);

CREATE TABLE allowed_agent_roles
(
    id         BIGSERIAL    NOT NULL PRIMARY KEY,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE,
    role_name  VARCHAR(255) NOT NULL,
    id_agent   BIGINT       NOT NULL REFERENCES acting_on_behalf (id)
);
