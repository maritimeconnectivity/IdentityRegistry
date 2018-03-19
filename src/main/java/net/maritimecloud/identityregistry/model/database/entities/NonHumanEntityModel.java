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
package net.maritimecloud.identityregistry.model.database.entities;

import io.swagger.annotations.ApiModelProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.Column;
import javax.persistence.MappedSuperclass;
import javax.validation.constraints.NotBlank;

@MappedSuperclass
@Getter
@Setter
@ToString
public abstract class NonHumanEntityModel extends EntityModel {
    @Column(name = "name", nullable = false)
    @NotBlank
    @ApiModelProperty(required = true)
    private String name;

    /** Copies this entity into the other */
    public NonHumanEntityModel copyTo(EntityModel target) {
        NonHumanEntityModel entity = (NonHumanEntityModel) super.copyTo(target);
        entity.setName(name);
        return entity;
    }

    /** Copies this entity into the other
     * Only update things that are allowed to change on update */
    public NonHumanEntityModel selectiveCopyTo(EntityModel target) {
        NonHumanEntityModel entity = (NonHumanEntityModel) super.selectiveCopyTo(target);
        entity.setName(name);
        return entity;
    }
}
