package net.maritimeconnectivity.identityregistry.utils;

import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.model.database.entities.MMS;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.model.database.entities.Vessel;
import net.maritimeconnectivity.identityregistry.model.database.entities.VesselAttribute;
import net.maritimeconnectivity.pki.PKIConstants;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class AttributesUtil {

    private AttributesUtil() {
        // empty private constructor as this class should not be instantiated
    }

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
