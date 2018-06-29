/*
 * Copyright 2018 Danish Maritime Authority
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.maritimecloud.identityregistry.services;

import net.maritimecloud.identityregistry.model.database.Agent;
import net.maritimecloud.identityregistry.repositories.AgentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AgentServiceImpl extends BaseServiceImpl<Agent> implements AgentService {

    protected AgentRepository repository;

    @Autowired
    public void setRepository(AgentRepository repository) {
        this.repository = repository;
    }

    @Transactional
    @Override
    public void deleteByOrg(Long id) {
        this.repository.deleteByIdOnBehalfOfOrganization(id);
    }

    @Override
    public Page<Agent> getAgentsByIdActingOrg(Long id, Pageable pageable) {
        return this.repository.findByIdActingOrganization(id, pageable);
    }

    @Override
    public List<Agent> getAgentsByIdActingOrg(Long id) {
        return this.repository.findByIdActingOrganization(id);
    }

    @Override
    public Page<Agent> getAgentsByIdOnBehalfOfOrg(Long id, Pageable pageable) {
        return this.repository.findByIdOnBehalfOfOrganization(id, pageable);
    }

    @Override
    public AgentRepository getRepository() {
        return this.repository;
    }
}
