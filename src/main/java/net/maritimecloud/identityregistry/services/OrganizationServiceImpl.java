/* Copyright 2015 Danish Maritime Authority.
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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import net.maritimecloud.identityregistry.model.Organization;
import net.maritimecloud.identityregistry.repositories.OrganizationRepository;

@Service
public class OrganizationServiceImpl implements OrganizationService {
    private OrganizationRepository OrganizationRepository;

    @Autowired
    public void setOrganizationRepository(OrganizationRepository OrganizationRepository) {
        this.OrganizationRepository = OrganizationRepository;
    }

    @Override
    public Iterable<Organization> listAllOrganizations() {
        return OrganizationRepository.findAll();
    }

    @Override
    public Organization getOrganizationById(Long id) {
        return OrganizationRepository.findOne(id);
    }

    @Override
    public Organization saveOrganization(Organization Organization) {
        return OrganizationRepository.save(Organization);
    }

    @Override
    public void deleteOrganization(Long id) {
        OrganizationRepository.delete(id);
    }

    @Override
	public Organization getOrganizationByShortName(String shortname) {
    	return OrganizationRepository.findByShortName(shortname);
    }

}
