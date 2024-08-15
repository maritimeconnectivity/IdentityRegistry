/*
 * Copyright 2017 Danish Maritime Authority.
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

import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.repositories.OrganizationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class OrganizationServiceImpl extends BaseServiceImpl<Organization> implements OrganizationService {

    private OrganizationRepository organizationRepository;

    @Autowired
    public void setOrganizationRepository(OrganizationRepository organizationRepository) {
        this.organizationRepository = organizationRepository;
    }

    @Override
    public Organization getOrganizationByMrn(String mrn) {
        return this.filterResult(organizationRepository.findByMrnAndApprovedTrue(mrn));
    }

    @Override
    public Organization getOrganizationById(Long id) {
        return this.filterResult(organizationRepository.findById(id).orElse(null));
    }

    @Override
    public Organization getOrganizationByMrnDisregardApproved(String mrn) {
        return this.filterResult(organizationRepository.findByMrn(mrn));
    }

    // Does not filter sensitive data from the result!
    @Override
    public Organization getOrganizationByMrnNoFilter(String mrn) {
        return organizationRepository.findByMrnAndApprovedTrue(mrn);
    }

    // Does not filter sensitive data from the result!
    @Override
    public Organization getOrganizationByIdNoFilter(Long id) {
        return organizationRepository.findById(id).orElse(null);
    }

    // This only shows approved organizations
    @Override
    public Page<Organization> listAllPage(Pageable pageable) {
        return this.filterResult(getRepository().findByApprovedTrue(pageable));
    }

    @Override
    public OrganizationRepository getRepository() {
        return this.organizationRepository;
    }

    @Override
    protected Organization filterResult(Organization data) {
        if (data != null && data.hasSensitiveFields() && (!isAuthorized() || !accessControlUtil.hasAccessToOrg(data.getMrn(), "ORG_ADMIN"))) {
            // If not authorized to see all we clean the object for sensitive data.
            log.debug("Clearing Sensitive Fields");
            data.clearSensitiveFields();
        }
        return data;
    }

    @Override
    protected Page<Organization> filterResult(Page<Organization> data) {
        if (data != null && !data.hasContent() && !accessControlUtil.hasRole("SITE_ADMIN")) {
            // If not authorized to see all we clean the object for sensitive data.
            boolean isAuthorized = isAuthorized();
            for (Organization org : data) {
                if (!isAuthorized || !accessControlUtil.hasAccessToOrg(org.getMrn(), "ORG_ADMIN")) {
                    log.debug("Clearing Sensitive Fields");
                    org.clearSensitiveFields();
                }
            }
        }
        return data;
    }

    public Page<Organization> getUnapprovedOrganizations(Pageable pageable) {
        return getRepository().findByApprovedFalse(pageable);
    }

    @Override
    public boolean existByMrn(String mrn) {
        return organizationRepository.existsByMrnIgnoreCase(mrn);
    }
}
