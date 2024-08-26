/*
 * Copyright 2024 Maritime Connectivity Platform Consortium
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

package net.maritimeconnectivity.identityregistry.utils;

import lombok.NoArgsConstructor;
import net.maritimeconnectivity.identityregistry.model.database.entities.Device;
import net.maritimeconnectivity.identityregistry.model.database.entities.MMS;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.model.database.entities.Vessel;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
@NoArgsConstructor
public class ExistsByMrnUtil {
    private EntityService<Device> deviceService;
    private EntityService<MMS> mmsService;
    private OrganizationService organizationService;
    private EntityService<Service> serviceService;
    private EntityService<User> userService;
    private EntityService<Vessel> vesselService;

    public boolean isMrnAlreadyUsed(String mrn) {
        return deviceService.existsByMrn(mrn) || mmsService.existsByMrn(mrn) || organizationService.existByMrn(mrn)
                || serviceService.existsByMrn(mrn) || userService.existsByMrn(mrn) || vesselService.existsByMrn(mrn);
    }

    @Autowired
    public ExistsByMrnUtil(EntityService<Device> deviceService, EntityService<MMS> mmsService, OrganizationService organizationService, EntityService<Service> serviceService, EntityService<User> userService, EntityService<Vessel> vesselService) {
        this.deviceService = deviceService;
        this.mmsService = mmsService;
        this.organizationService = organizationService;
        this.serviceService = serviceService;
        this.userService = userService;
        this.vesselService = vesselService;
    }

    @Autowired
    public void setDeviceService(EntityService<Device> deviceService) {
        this.deviceService = deviceService;
    }

    @Autowired
    public void setMmsService(EntityService<MMS> mmsService) {
        this.mmsService = mmsService;
    }

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @Autowired
    public void setServiceService(EntityService<Service> serviceService) {
        this.serviceService = serviceService;
    }

    @Autowired
    public void setUserService(EntityService<User> userService) {
        this.userService = userService;
    }

    @Autowired
    public void setVesselService(EntityService<Vessel> vesselService) {
        this.vesselService = vesselService;
    }
}
