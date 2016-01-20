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

import net.maritimecloud.identityregistry.model.Device;
import net.maritimecloud.identityregistry.repositories.DeviceRepository;

@Service
public class DeviceServiceImpl implements DeviceService {
    private DeviceRepository DeviceRepository;

    @Autowired
    public void setDeviceRepository(DeviceRepository DeviceRepository) {
        this.DeviceRepository = DeviceRepository;
    }

    @Override
    public Iterable<Device> listAllDevices() {
        return DeviceRepository.findAll();
    }

    @Override
    public Device getDeviceById(Long id) {
        return DeviceRepository.findOne(id);
    }

    @Override
    public Device saveDevice(Device device) {
        return DeviceRepository.save(device);
    }

    @Override
    public void deleteDevice(Long id) {
        DeviceRepository.delete(id);
    }

    @Override
    public List<Device> listOrgDevices(int orgId) {
        return DeviceRepository.findByidOrganization(orgId);
    }
}

