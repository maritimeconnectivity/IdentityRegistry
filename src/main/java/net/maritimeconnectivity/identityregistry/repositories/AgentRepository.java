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

package net.maritimeconnectivity.identityregistry.repositories;

import net.maritimeconnectivity.identityregistry.model.database.Agent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface AgentRepository extends CrudRepository<Agent, Long> {

    Page<Agent> findByIdActingOrganization(Long orgId, Pageable pageable);

    Page<Agent> findByIdOnBehalfOfOrganization(Long id, Pageable pageable);

    List<Agent> findByIdActingOrganization(Long orgId);

    List<Agent> findByIdOnBehalfOfOrganizationAndIdActingOrganization(Long onBehalfOfId, Long actingId);

    void deleteByIdOnBehalfOfOrganization(Long id);

    void deleteByIdActingOrganization(Long id);
}
