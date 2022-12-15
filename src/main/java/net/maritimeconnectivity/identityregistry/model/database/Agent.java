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

package net.maritimeconnectivity.identityregistry.model.database;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.OneToMany;
import jakarta.persistence.PostPersist;
import jakarta.persistence.PostUpdate;
import jakarta.persistence.Table;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "acting_on_behalf")
@Getter
@Setter
@Schema(description = "Model object representing an agent")
public class Agent extends TimestampModel {

    /**
     * The organization that is acting on behalf of the other organization
     */
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The id of the organization that should be given agent permissions")
    @Column(name = "id_acting", nullable = false)
    private Long idActingOrganization;

    /**
     * The organization that is being acted on behalf of
     */
    @Schema(description = "The id of the organization that is giving agent permissions")
    @Column(name = "id_on_behalf_of", nullable = false)
    private Long idOnBehalfOfOrganization;

    @Schema(description = "The set of roles that this agent is allowed to have")
    @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL, mappedBy = "agent", orphanRemoval = true)
    private Set<AllowedAgentRole> allowedRoles;

    /** Copies this agent into the other */
    public Agent copyTo(Agent agent) {
        Objects.requireNonNull(agent);
        agent.setIdActingOrganization(this.idActingOrganization);
        agent.setIdOnBehalfOfOrganization(this.idOnBehalfOfOrganization);
        agent.getAllowedRoles().clear();
        agent.getAllowedRoles().addAll(allowedRoles);
        agent.setChildIds();
        return agent;
    }

    @PostPersist
    @PostUpdate
    public void setChildIds() {
        if (this.allowedRoles != null && !this.allowedRoles.isEmpty()) {
            for (AllowedAgentRole ar : this.allowedRoles) {
                ar.setAgent(this);
            }
        }
    }
}
