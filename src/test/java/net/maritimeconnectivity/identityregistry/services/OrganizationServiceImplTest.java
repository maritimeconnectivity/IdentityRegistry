/*
 * Copyright 2026 Maritime Connectivity Platform Consortium
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package net.maritimeconnectivity.identityregistry.services;

import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.repositories.OrganizationRepository;
import net.maritimeconnectivity.identityregistry.utils.AccessControlUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

// Regression test for the inverted sanitization condition fixed in commit "Fix inverted sanitization logic":
// OrganizationServiceImpl.filterResult(Page) used to only sanitize *empty* pages (!data.hasContent()) instead
// of non-empty ones, so pages of organizations with content were returned to unauthorized callers without
// stripping sensitive fields.
class OrganizationServiceImplTest {

    private OrganizationServiceImpl organizationService;
    private AccessControlUtil accessControlUtil;

    @BeforeEach
    void setUp() {
        organizationService = new OrganizationServiceImpl();
        organizationService.setOrganizationRepository(mock(OrganizationRepository.class));
        accessControlUtil = mock(AccessControlUtil.class);
        organizationService.setAccessControlUtil(accessControlUtil);
    }

    private static Organization newOrganizationWithSensitiveData() {
        Organization org = new Organization();
        org.setMrn("urn:mrn:mcp:org:idp1:test");
        org.setFederationType("own-idp");
        org.setIdentityProviderAttributes(new HashSet<>());
        return org;
    }

    @Test
    void filterResultSanitizesNonEmptyPageWhenNotSiteAdminAndNotAuthorized() {
        when(accessControlUtil.hasRole("SITE_ADMIN")).thenReturn(false);
        when(accessControlUtil.hasAnyRoles(anyList())).thenReturn(false);
        when(accessControlUtil.hasAccessToOrg(anyString(), anyString())).thenReturn(false);

        Organization org = newOrganizationWithSensitiveData();
        Page<Organization> page = new PageImpl<>(List.of(org));

        organizationService.filterResult(page);

        assertNull(org.getFederationType(),
                "Sensitive fields should be cleared for a non-empty page when the caller lacks access");
    }

    @Test
    void filterResultLeavesNonEmptyPageUntouchedForSiteAdmin() {
        when(accessControlUtil.hasRole("SITE_ADMIN")).thenReturn(true);

        Organization org = newOrganizationWithSensitiveData();
        Page<Organization> page = new PageImpl<>(List.of(org));

        organizationService.filterResult(page);

        assertEquals("own-idp", org.getFederationType(),
                "A SITE_ADMIN should see organizations without sensitive fields being cleared");
    }

    @Test
    void filterResultLeavesEmptyPageUntouched() {
        when(accessControlUtil.hasRole("SITE_ADMIN")).thenReturn(false);

        Page<Organization> emptyPage = new PageImpl<>(Collections.emptyList());

        Page<Organization> result = organizationService.filterResult(emptyPage);

        assertFalse(result.hasContent());
    }
}
