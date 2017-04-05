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
package net.maritimecloud.identityregistry.services;

import net.maritimecloud.identityregistry.model.database.entities.Service;
import net.maritimecloud.identityregistry.repositories.ServiceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

@org.springframework.stereotype.Service
public class ServiceServiceImpl extends EntityServiceImpl<Service> implements ServiceService {

    @Autowired
    private ServiceRepository repository;

    @Override
    public Page<Service> listPageFromOrg(Long orgId, Pageable pageable) {
        Page<Service> ret = repository.findByidOrganization(orgId, pageable);
        ret = this.filterResult(ret);
        return ret;
    }

    public Service getServiceByMrnAndVersion(String mrn, String version) {
        return repository.getByMrnAndInstanceVersion(mrn, version);
    }

    public Service getByMrn(String mrn) {
        throw new UnsupportedOperationException("Single services cannot be fetched using only MRN!");
    }

    public Page<Service> getServicesByMrn(String mrn, Pageable pageable) {
        Page<Service> ret = repository.findByMrn(mrn, pageable);
        ret = this.filterResult(ret);
        return ret;
    }

    @Override
    @Transactional
    public Service save(Service service) {
        return repository.save(service);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        repository.delete(id);
    }

    @Override
    public Service getById(Long id) {
        Service ret = repository.findOne(id);
        return filterResult(ret);
    }

}

