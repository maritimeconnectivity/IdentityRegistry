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
package net.maritimeconnectivity.identityregistry.services;

import net.maritimeconnectivity.identityregistry.model.database.TimestampModel;
import net.maritimeconnectivity.identityregistry.repositories.EntityRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public abstract class EntityServiceImpl<T extends TimestampModel> extends BaseServiceImpl<T> implements EntityService<T> {

    protected EntityRepository<T> repository;

    public List<T> listAllFromOrg(Long id) {
        return this.getRepository().findByIdOrganization(id);
    }

    public Page<T> listPageFromOrg(Long id, Pageable pageable) {
        return this.getRepository().findByidOrganization(id, pageable);
    }

    @Transactional
    public void deleteByOrg(Long id) {
        this.getRepository().deleteByidOrganization(id);
    }

    public EntityRepository<T> getRepository() {
        return this.repository;
    }

    public T getByMrn(String mrn) {
        return this.getRepository().getByMrnIgnoreCase(mrn);
    }

    public T getByMrnSubsidiary(String mrn){
        return this.getRepository().getByMrnSubsidiaryIgnoreCase(mrn);
    }
}
