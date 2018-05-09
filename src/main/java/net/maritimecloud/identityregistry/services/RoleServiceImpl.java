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

import net.maritimecloud.identityregistry.model.database.Role;
import net.maritimecloud.identityregistry.repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class RoleServiceImpl extends BaseServiceImpl<Role> implements RoleService {

    protected RoleRepository repository;

    @Autowired
    public void setRoleRepository(RoleRepository roleRepository) {
        this.repository = roleRepository;
    }

    @Override
    public List<Role> getRolesByIdOrganizationAndPermission(Long idOrganization, String permission) {
        return repository.findByIdOrganizationAndPermission(idOrganization, permission);
    }

    public List<Role> listFromOrg(Long id) {
        return this.getRepository().findByidOrganization(id);
    }

    @Transactional
    public void deleteByOrg(Long id) {
        this.getRepository().deleteByidOrganization(id);
    }

    public RoleRepository getRepository() {
        return this.repository;
    }

}
