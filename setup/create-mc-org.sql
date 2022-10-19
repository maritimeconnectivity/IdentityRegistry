#--- Create the Bootstrap organization
INSERT INTO `organizations` (name, mrn, email, address, country, url, approved, federation_type, certificate_authority, created_at, updated_at) VALUES ('Bootstrap Org', 'urn:mrn:mcp:org:idp1:bootstrap', 'info@maritimeconnectivity.net', '1 Maritime Street, The Eight Ocean', 'Denmark', 'https://maritimeconnectivity.net', true, 'external-idp', 'urn:mrn:mcp:ca:idp1:mcp-idreg', NOW(), NOW());
#--- Create the roles for the Bootstrap organization
INSERT INTO `roles` (id_organization, role_name, permission, created_at, updated_at) VALUES ((SELECT id FROM `organizations` WHERE mrn='urn:mrn:mcp:org:idp1:bootstrap'), 'ROLE_SITE_ADMIN', 'MCPADMIN', NOW(), NOW());
