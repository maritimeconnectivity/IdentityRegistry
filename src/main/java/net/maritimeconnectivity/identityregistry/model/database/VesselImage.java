/*
 * Copyright 2017 Danish Maritime Authority
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

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.database.entities.Vessel;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import java.util.Objects;

@Entity
@Table(name="vessel_images")
@Getter
@Setter
@ToString(exclude = "vessel")
@NoArgsConstructor
public class VesselImage extends TimestampModel {

    @Column(name = "image", nullable = false)
    private byte[] image;

    @JsonIgnore
    @OneToOne(mappedBy = "image")
    private Vessel vessel;

    public VesselImage copyTo(VesselImage vesselImage) {
        Objects.requireNonNull(vesselImage);
        vesselImage.setId(this.id);
        vesselImage.setVessel(this.vessel);
        vesselImage.setImage(this.image);
        return vesselImage;
    }
}
