/*
 * Copyright 2021 Maritime Connectivity Platform Consortium.
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

package net.maritimeconnectivity.identityregistry.model.database;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.validators.InPredefinedList;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;

@Entity
@Table(name = "allowed_agent_roles")
@Getter
@Setter
@ToString(exclude = "agent")
@NoArgsConstructor
@Schema(description = "Model object for representing a role that an agent is allowed to have")
public class AllowedAgentRole extends TimestampModel {

    @Schema(description = "The role that you want the agent to be allowed to have", allowableValues = {"ROLE_ORG_ADMIN", "ROLE_ENTITY_ADMIN", "ROLE_USER_ADMIN",
            "ROLE_VESSEL_ADMIN", "ROLE_SERVICE_ADMIN", "ROLE_DEVICE_ADMIN", "ROLE_MMS_ADMIN", "ROLE_USER"}, requiredMode = Schema.RequiredMode.REQUIRED)
    @InPredefinedList(acceptedValues = {"ROLE_ORG_ADMIN", "ROLE_ENTITY_ADMIN", "ROLE_USER_ADMIN",
            "ROLE_VESSEL_ADMIN", "ROLE_SERVICE_ADMIN", "ROLE_DEVICE_ADMIN", "ROLE_MMS_ADMIN", "ROLE_USER"})
    @Column(name = "role_name", nullable = false)
    @NotNull
    private String roleName;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_agent", nullable = false)
    private Agent agent;

    @JsonIgnore
    @Override
    public Long getId() {
        return id;
    }
}
