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
package net.maritimeconnectivity.identityregistry.model.database;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.JsonSerializable;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import java.time.Instant;
import java.util.Date;

import static io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY;

@MappedSuperclass
@Getter
@Setter
@ToString
public abstract class TimestampModel implements JsonSerializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Setter(AccessLevel.PROTECTED)
    @Column(name = "id", nullable = false)
    @Schema(description = "The ID of the entity in the form of a sequential integer", accessMode = READ_ONLY)
    protected Long id;

    @Column(name = "created_at", updatable = false)
    @Schema(description = "The time that the entity was created", accessMode = READ_ONLY)
    protected Date createdAt;

    @Column(name = "updated_at")
    @Schema(description = "The time that the entity was last updated", accessMode = READ_ONLY)
    protected Date updatedAt;

    /**
     * Called at creation, set created_at and updated_at timestamp
     */
    @PrePersist
    void createdAt() {
        this.createdAt = this.updatedAt = Date.from(Instant.now());
    }

    /**
     * Called on update, set updated_at timestamp
     */
    @PreUpdate
    void updatedAt() {
        this.updatedAt = Date.from(Instant.now());
    }

    // Override if needed - use to detect if blanking of sensitive fields are needed
    public boolean hasSensitiveFields() {
        return false;
    }

    // Override if needed - use when blanking sensitive fields so that users without privileges
    // can see object with non-sensitive data.
    public void clearSensitiveFields() {
    }
}
