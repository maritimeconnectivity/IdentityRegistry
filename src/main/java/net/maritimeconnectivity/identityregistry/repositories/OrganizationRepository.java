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
package net.maritimeconnectivity.identityregistry.repositories;

import net.maritimeconnectivity.identityregistry.model.database.Organization;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;

import java.util.Optional;

public interface OrganizationRepository extends PagingAndSortingRepository<Organization, Long>, CrudRepository<Organization, Long> {
    Organization findByMrnAndApprovedTrue(String mrn);

    Organization findByMrn(String mrn);

    Optional<Organization> findById(Long id);

    Page<Organization> findByApprovedFalse(Pageable pageable);

    Page<Organization> findByApprovedTrue(Pageable pageable);

}
