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
package net.maritimecloud.identityregistry.services;

import net.maritimecloud.identityregistry.model.database.Organization;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface OrganizationService extends BaseService<Organization>{
    Organization getOrganizationByMrn(String mrn);

    Organization getOrganizationById(Long id);

    Organization getOrganizationByMrnDisregardApproved(String mrn);
    /* Does not filter sensitive data from the result! */
    Organization getOrganizationByMrnNoFilter(String mrn);

    Page<Organization> getUnapprovedOrganizations(Pageable page);

    Page<Organization> listAllPage(Pageable pageable);
}