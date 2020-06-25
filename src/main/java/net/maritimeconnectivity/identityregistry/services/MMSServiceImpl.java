/*
 * Copyright 2020 Maritime Connectivity Platform Consortium.
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

import net.maritimeconnectivity.identityregistry.model.database.entities.MMS;
import net.maritimeconnectivity.identityregistry.repositories.MMSRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class MMSServiceImpl extends EntityServiceImpl<MMS> implements MMSService {
    @Autowired
    private MMSRepository repository;

    @Override
    public MMS getByUrl(String url) {
        return this.repository.getByUrl(url);
    }

    public MMS getByMrn(String mrn) {
        return this.repository.getByMrnIgnoreCase(mrn);
    }

    @Override
    public MMS getByMrnSubsidiary(String mrn) {
        return this.repository.getByMrnSubsidiaryIgnoreCase(mrn);
    }

    @Autowired
    public void setMMSRepository(MMSRepository mmsRepository) { this.repository = mmsRepository; }
}

