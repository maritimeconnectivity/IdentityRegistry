/* Copyright 2016 Danish Maritime Authority.
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
package net.maritimecloud.identityregistry.services;

import com.google.common.collect.Lists;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.repositories.OrganizationRepository;

import java.util.List;

@Service
public class OrganizationServiceImpl extends BaseServiceImpl<Organization> implements OrganizationService {
    private static final Logger logger = LoggerFactory.getLogger(OrganizationServiceImpl.class);

    private OrganizationRepository organizationRepository;

    @Autowired
    public void setOrganizationRepository(OrganizationRepository OrganizationRepository) {
        this.organizationRepository = OrganizationRepository;
    }

    @Override
    public Organization getOrganizationByMrn(String mrn) {
        return this.filterResult(organizationRepository.findByMrnAndApprovedTrue(mrn));
    }

    @Override
    public Organization getOrganizationByMrnDisregardApproved(String mrn) {
        return this.filterResult(organizationRepository.findByMrn(mrn));
    }

    /* Does not filter sensitive data from the result! */
    public Organization getOrganizationByMrnNoFilter(String mrn) {
        return organizationRepository.findByMrnAndApprovedTrue(mrn);
    }

    @Override
    public List<Organization> listAll() {
        return this.filterResult(Lists.newArrayList(getRepository().findAll()));
    }

    @Override
    public OrganizationRepository getRepository() {
        return this.organizationRepository;
    }

    @Override
    protected Organization filterResult(Organization data) {
        if (data != null && data.hasSensitiveFields()) {
            // If not authorized to see all we clean the object for sensitive data.
            if (!isAuthorized() || !AccessControlUtil.hasAccessToOrg(data.getMrn())) {
                logger.debug("Clearing Sensitive Fields");
                data.clearSensitiveFields();
            }
        }
        return data;
    }

    @Override
    protected List<Organization> filterResult(List<Organization> data) {
        if (data != null && !data.isEmpty() && data.get(0).hasSensitiveFields() && !accessControlUtil.hasRole("SITE_ADMIN")) {
            // If not authorized to see all we clean the object for sensitive data.
            boolean isAuthorized = isAuthorized();
            for (Organization org : data) {
                if (!isAuthorized || !AccessControlUtil.hasAccessToOrg(org.getMrn())) {
                    logger.debug("Clearing Sensitive Fields");
                    org.clearSensitiveFields();
                }
            }
        }
        return data;
    }

    public List<Organization> getUnapprovedOrganizations() {
        return getRepository().findByApprovedFalse();
    }
}