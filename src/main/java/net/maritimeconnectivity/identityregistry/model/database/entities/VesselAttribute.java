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
package net.maritimeconnectivity.identityregistry.model.database.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.database.TimestampModel;
import net.maritimeconnectivity.identityregistry.validators.InPredefinedList;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import java.util.Date;

/**
 * Model object representing a vessel attribute
 */

@Entity
@Table(name = "vessel_attributes")
@Getter
@Setter
@ToString(exclude = "vessel")
@NoArgsConstructor
@Schema(description = "Model object representing a vessel attribute")
public class VesselAttribute extends TimestampModel {

    @Schema(description = "Vessel attribute name", required = true, allowableValues = {"imo-number", "mmsi-number", "callsign", "flagstate", "ais-class", "port-of-register"})
    @InPredefinedList(acceptedValues = {"imo-number", "mmsi-number", "callsign", "flagstate", "ais-class", "port-of-register"})
    @Column(name = "attribute_name", nullable = false)
    @NotNull
    private String attributeName;

    @Schema(description = "Vessel attribute value", required = true)
    @Column(name = "attribute_value", nullable = false)
    @NotNull
    private String attributeValue;

    @Schema(description = "When the attribute is valid from")
    @Column(name = "start")
    private Date start;

    @Schema(description = "When the attribute is valid until")
    @Column(name = "valid_until")
    private Date end;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_vessel", nullable = false)
    private Vessel vessel;

    /******************************/
    /** Getters and setters      **/
    /******************************/

    @Override
    @JsonIgnore
    public Long getId() {
        return id;
    }

    public void setAttributeName(String attributeName) {
        if (attributeName != null) {
            this.attributeName = attributeName.toLowerCase();
        }
    }
}
