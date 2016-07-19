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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.repositories.OrganizationRepository;

import java.util.List;

@Service
public class OrganizationServiceImpl extends BaseServiceImpl<Organization> implements OrganizationService {
    private OrganizationRepository organizationRepository;

    @Autowired
    public void setOrganizationRepository(OrganizationRepository OrganizationRepository) {
        this.organizationRepository = OrganizationRepository;
    }

    @Override
    public List<Organization> listAll() {
        List<Organization> ret = Lists.newArrayList(organizationRepository.findAll());
        return this.filterResult(ret);
    }

    @Override
    public Organization getById(Long id) {
        Organization ret = organizationRepository.findOne(id);
        return this.filterResult(ret);
    }

    @Override
    public Organization save(Organization Organization) {
        return organizationRepository.save(Organization);
    }

    @Override
    public void delete(Long id) {
        organizationRepository.delete(id);
    }

    @Override
    public Organization getOrganizationByShortName(String shortname) {
        return organizationRepository.findByShortName(shortname);
    }

    @Override
    public OrganizationRepository getRepository() {
        return this.organizationRepository;
    }
}