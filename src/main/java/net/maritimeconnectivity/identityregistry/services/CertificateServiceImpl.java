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
import net.maritimeconnectivity.identityregistry.repositories.CertificateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;

@Service
public class CertificateServiceImpl implements CertificateService {
    private CertificateRepository certificateRepository;

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Override
    public Certificate getCertificateBySerialNumber(BigInteger serialNumber) {
        return certificateRepository.getBySerialNumber(serialNumber);
    }

    @Override
    public Certificate saveCertificate(Certificate certificate) {
        return certificateRepository.save(certificate);
    }

    @Override
    public void deleteCertificate(Long id) {
        throw new UnsupportedOperationException("Deletion of certificates is not supported, please revoke them");
    }

    @Override
    public List<Certificate> listVesselCertificate(Vessel vessel) {
        return certificateRepository.findByvessel(vessel);
    }
    
    @Override
    public List<Certificate> listUserCertificate(User user) {
        return certificateRepository.findByuser(user);
    }
    
    @Override
    public List<Certificate> listDeviceCertificate(Device device) {
        return certificateRepository.findBydevice(device);
    }

    @Override
    public List<Certificate> listRevokedCertificate(String caAlias) {
        Date now = new Date();
        return certificateRepository.findByCertificateAuthorityIgnoreCaseAndRevokedTrueAndRevokedAtIsBefore(caAlias, now);
    }

}

