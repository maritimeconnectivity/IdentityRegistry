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
package net.maritimecloud.identityregistry.model.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;
import net.maritimecloud.identityregistry.model.database.entities.Service;
import net.maritimecloud.identityregistry.services.OrganizationServiceImpl;

@Getter
@Setter
public class ServiceBasicModel {
    private String instanceVersion;
    private String mrn;
    private String name;
    private String orgMrn;
    @JsonIgnore
    private static OrganizationServiceImpl organizationService = new OrganizationServiceImpl();

    public ServiceBasicModel(Service service) {
        this.instanceVersion = service.getInstanceVersion();
        this.mrn = service.getMrn();
        this.name = service.getName();
        String orgMrn = organizationService.getById(service.getIdOrganization()).getMrn();
        this.orgMrn = orgMrn;
    }
}
