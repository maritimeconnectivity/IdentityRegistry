/* Copyright 2016 Danish Maritime Authority.
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
package net.maritimecloud.identityregistry.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Service;

import net.maritimecloud.identityregistry.model.database.entities.Service;
import net.maritimecloud.identityregistry.repositories.ServiceRepository;

@org.springframework.stereotype.Service
public class ServiceServiceImpl implements ServiceService {
    private ServiceRepository ServiceRepository;

    @Autowired
    public void setServiceRepository(ServiceRepository ServiceRepository) {
        this.ServiceRepository = ServiceRepository;
    }

    @Override
    public Iterable<Service> listAllServices() {
        return ServiceRepository.findAll();
    }

    @Override
    public Service getServiceById(Long id) {
        return ServiceRepository.findOne(id);
    }

    @Override
    public Service saveService(Service device) {
        return ServiceRepository.save(device);
    }

    @Override
    public void deleteService(Long id) {
        ServiceRepository.delete(id);
    }

    @Override
    public List<Service> listOrgServices(Long orgId) {
        return ServiceRepository.findByidOrganization(orgId);
    }
}

