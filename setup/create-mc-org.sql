USE identity_registry;
#--- Create the Maritime Cloud organization
INSERT INTO `organizations` (name, mrn, email, address, country, url, approved, federation_type, certificate_authority, created_at, updated_at) VALUES
    ('Maritime Cloud', 'urn:mrn:mcl:org:maritimecloud', 'info@maritimecloud.net', '1 Martime Street, The Eight Ocean', 'Denmark', 'http://maritimecloud.net', 1, 'external-idp', 'urn:mrn:mcl:ca:maritimecloud-idreg', NOW(), NOW());
#--- Create the roles for the Maritime Cloud organization
INSERT INTO `roles` (id_organization, role_name, permission, created_at, updated_at) VALUES
    ((SELECT id FROM `organizations` WHERE mrn='urn:mrn:mcl:org:maritimecloud'), 'ROLE_SITE_ADMIN', 'MCADMIN', NOW(), NOW());
