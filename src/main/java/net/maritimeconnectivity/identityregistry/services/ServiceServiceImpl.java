/*
 * Copyright 2017 Danish Maritime Authority.
 * Copyright 2020 Maritime Connectivity Platform Consortium
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
package net.maritimeconnectivity.identityregistry.services;

import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.repositories.ServiceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

@org.springframework.stereotype.Service
public class ServiceServiceImpl extends EntityServiceImpl<Service> implements ServiceService {

    private ServiceRepository serviceRepository;

    @Autowired
    public void setServiceRepository(ServiceRepository serviceRepository) {
        this.serviceRepository = serviceRepository;
    }

    @Override
    public Page<Service> listPageFromOrg(Long orgId, Pageable pageable) {
        Page<Service> ret = serviceRepository.findByidOrganization(orgId, pageable);
        return this.filterResult(ret);
    }

    @Override
    public List<Service> listAllFromOrg(Long id) {
        List<Service> ret = serviceRepository.findByidOrganization(id);
        return this.filterResult(ret);
    }

    @Override
    public Service getServiceByMrnAndVersion(String mrn, String version) {
        return serviceRepository.getByMrnIgnoreCaseAndInstanceVersion(mrn, version);
    }

    @Override
    public Page<Service> getServicesByMrnPrefix(String mrn, Pageable pageable) {
        Page<Service> ret = serviceRepository.findByMrnStartingWithIgnoreCase(mrn, pageable);
        return this.filterResult(ret);
    }

    @Override
    public List<Service> getServicesByMrnPrefix(String mrn) {
        List<Service> services = serviceRepository.findByMrnStartingWithIgnoreCase(mrn);
        return this.filterResult(services);
    }

    @Override
    public Service getNewestServiceByMrnPrefix(String mrn) {
        List<Service> services = serviceRepository.findByMrnIgnoreCase(mrn);
        if (services.size() == 1) {
            return services.getFirst();
        }

        services = getServicesByMrnPrefix(mrn);
        if (services.size() == 1) {
            return services.getFirst();
        }

        int mrnSplitLength = mrn.split(":").length;

        services = services.stream()
                .filter(s -> s.getMrn().split(":").length == mrnSplitLength + 1)
                .sorted(Comparator.comparing(Service::getCreatedAt)).toList();
        return services.isEmpty() ? null : services.getFirst();
    }

    @Transactional
    @Override
    public void deleteByOrg(Long id) {
        serviceRepository.deleteByidOrganization(id);
    }

    @Override
    @Transactional
    public Service save(Service service) {
        return serviceRepository.save(service);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        serviceRepository.deleteById(id);
    }

    @Override
    public Service getById(Long id) {
        Optional<Service> ret = serviceRepository.findById(id);
        return filterResult(ret.orElse(null));
    }

    @Override
    public Service getByMrn(String mrn) {
        return getServiceByMrnAndVersion(mrn, null);
    }

    @Override
    public boolean existsByMrn(String mrn) {
        return serviceRepository.existsByMrnIgnoreCase(mrn);
    }
}

