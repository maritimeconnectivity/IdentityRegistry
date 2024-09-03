/*
 * Copyright 2018 Danish Maritime Authority
 * Copyright 2020 Maritime Connectivity Platform Consortium
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

package net.maritimeconnectivity.identityregistry.services;

import net.maritimeconnectivity.identityregistry.model.database.Agent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface AgentService extends BaseService<Agent> {

    void deleteByOrg(Long id);

    Page<Agent> getAgentsByIdActingOrg(Long id, Pageable pageable);

    List<Agent> getAgentsByIdActingOrg(Long id);

    Page<Agent> getAgentsByIdOnBehalfOfOrg(Long id, Pageable pageable);

    List<Agent> getAgentsByIdOnBehalfOfOrgAndIdActingOrg(Long idOnBehalfOf, Long idActing);
}
