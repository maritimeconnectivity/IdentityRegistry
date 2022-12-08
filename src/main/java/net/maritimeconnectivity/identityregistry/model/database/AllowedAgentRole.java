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
            "ROLE_VESSEL_ADMIN", "ROLE_SERVICE_ADMIN", "ROLE_DEVICE_ADMIN", "ROLE_MMS_ADMIN", "ROLE_USER"}, required = true)
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
