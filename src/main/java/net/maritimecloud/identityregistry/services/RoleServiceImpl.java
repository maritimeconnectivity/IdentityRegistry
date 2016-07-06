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

import net.maritimecloud.identityregistry.model.Role;
import net.maritimecloud.identityregistry.repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RoleServiceImpl implements RoleService {
    private RoleRepository RoleRepository;

    @Autowired
    public void setRoleRepository(RoleRepository RoleRepository) {
        this.RoleRepository = RoleRepository;
    }

    @Override
    public Iterable<Role> listAllRoles() {
        return RoleRepository.findAll();
    }

    @Override
    public Role getRoleById(Long id) {
        return RoleRepository.findOne(id);
    }

    @Override
    public Role saveRole(Role role) {
        return RoleRepository.save(role);
    }

    @Override
    public void deleteRole(Long id) {
        RoleRepository.delete(id);
    }

    @Override
    public List<Role> listOrgRoles(Long orgId) {
        return RoleRepository.findByidOrganization(orgId);
    }
}

