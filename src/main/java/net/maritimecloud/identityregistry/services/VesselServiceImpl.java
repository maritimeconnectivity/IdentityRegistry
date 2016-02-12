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
import org.springframework.stereotype.Service;

import net.maritimecloud.identityregistry.model.Vessel;
import net.maritimecloud.identityregistry.repositories.VesselRepository;

@Service
public class VesselServiceImpl implements VesselService {
    private VesselRepository VesselRepository;

    @Autowired
    public void setVesselRepository(VesselRepository VesselRepository) {
        this.VesselRepository = VesselRepository;
    }

    @Override
    public Iterable<Vessel> listAllVessels() {
        return VesselRepository.findAll();
    }

    @Override
    public Vessel getVesselById(Long id) {
        return VesselRepository.findOne(id);
    }

    @Override
    public Vessel saveVessel(Vessel vessel) {
        return VesselRepository.save(vessel);
    }

    @Override
    public void deleteVessel(Long id) {
        VesselRepository.delete(id);
    }

    @Override
    public List<Vessel> listOrgVessels(int orgId) {
        return VesselRepository.findByidOrganization(orgId);
    }
}
