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

package net.maritimeconnectivity.identityregistry.utils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.model.database.entities.MMS;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.model.database.entities.Vessel;
import net.maritimeconnectivity.identityregistry.model.database.entities.VesselAttribute;
import net.maritimeconnectivity.pki.PKIConstants;

import java.util.HashMap;
import java.util.Map;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public class AttributesUtil {

    /**
     * Get the special attributes of an entity
     *
     * @param certOwner
     * @return the attributes of an entity
     */
    public static Map<String, String> getAttributes(CertificateModel certOwner) {
        HashMap<String, String> attrs = new HashMap<>();
        if (certOwner instanceof Vessel vessel) {
            attrs = getAttributesVessel(vessel);
        } else if (certOwner instanceof Service service) {
            attrs = getAttributesService(service);
        } else if (certOwner instanceof MMS mms) {
            attrs = getAttributeMMS(mms);
        }
        return attrs;
    }

    /**
     * Get the special attributes of a vessel
     *
     * @param vessel
     * @return the attributes of a vessel
     */
    private static HashMap<String, String> getAttributesVessel(Vessel vessel) {
        HashMap<String, String> attrs = new HashMap<>();
        for (VesselAttribute attr : vessel.getAttributes()) {
            String attrName = attr.getAttributeName().toLowerCase();
            switch (attrName) {
                case "callsign" -> attrs.put(PKIConstants.MC_OID_CALLSIGN, attr.getAttributeValue());
                case "imo-number" -> attrs.put(PKIConstants.MC_OID_IMO_NUMBER, attr.getAttributeValue());
                case "mmsi-number" -> attrs.put(PKIConstants.MC_OID_MMSI_NUMBER, attr.getAttributeValue());
                case "flagstate" -> attrs.put(PKIConstants.MC_OID_FLAGSTATE, attr.getAttributeValue());
                case "ais-class" -> attrs.put(PKIConstants.MC_OID_AIS_SHIPTYPE, attr.getAttributeValue());
                case "port-of-register" -> attrs.put(PKIConstants.MC_OID_PORT_OF_REGISTER, attr.getAttributeValue());
                default -> log.debug("Unexpected attribute value: " + attrName);
            }
        }
        return attrs;
    }

    /**
     * Get the special attributes of a service
     *
     * @param service
     * @return the special attributes of a service
     */
    private static HashMap<String, String> getAttributesService(Service service) {
        HashMap<String, String> attrs = new HashMap<>();
        String certDomainName = service.getCertDomainName();
        if (certDomainName != null && !certDomainName.trim().isEmpty()) {
            String[] domainNames = certDomainName.split(",");
            for (String domainName : domainNames) {
                attrs.put(PKIConstants.X509_SAN_DNSNAME, domainName.trim());
            }
        }
        Vessel vessel = service.getVessel();
        if (vessel != null) {
            attrs.putAll(getAttributesVessel(vessel));
            attrs.put(PKIConstants.MC_OID_SHIP_MRN, vessel.getMrn());
        }
        return attrs;
    }

    /**
     * Get the url attributes of a mms
     *
     * @param mms
     * @return the url attributes of a mms
     */
    private static HashMap<String, String> getAttributeMMS(MMS mms) {
        HashMap<String, String> attrs = new HashMap<>();
        String mmsUrl = mms.getUrl();
        if (mmsUrl != null && !mmsUrl.isEmpty()) {
            attrs.put(PKIConstants.MC_OID_URL, mmsUrl);
        }
        return attrs;
    }
}
