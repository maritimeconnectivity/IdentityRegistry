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

import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.entities.Device;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.model.database.entities.Vessel;

import java.math.BigInteger;
import java.util.List;

public interface CertificateService {
    Certificate getCertificateBySerialNumber(BigInteger serialNumber);

    Certificate saveCertificate(Certificate certificate);

    void deleteCertificate(Long id);

    List<Certificate> listVesselCertificate(Vessel vessel);

    List<Certificate> listUserCertificate(User user);
    
    List<Certificate> listDeviceCertificate(Device device);

    List<Certificate> listRevokedCertificate(String caAlias);
}
