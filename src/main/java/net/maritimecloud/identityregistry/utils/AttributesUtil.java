package net.maritimecloud.identityregistry.utils;

import lombok.extern.slf4j.Slf4j;
import net.maritimecloud.identityregistry.model.database.CertificateModel;
import net.maritimecloud.identityregistry.model.database.entities.Service;
import net.maritimecloud.identityregistry.model.database.entities.Vessel;
import net.maritimecloud.identityregistry.model.database.entities.VesselAttribute;
import net.maritimecloud.pki.PKIConstants;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class AttributesUtil {

    private AttributesUtil() {

    }

    /**
     * Get the special attributes of an entity
     *
     * @param certOwner
     * @return the attributes of an entity
     */
    public static Map<String, String> getAttributes(CertificateModel certOwner) {
        HashMap<String, String> attrs = new HashMap<>();
        if (certOwner instanceof Vessel) {
            attrs = getAttributesVessel((Vessel) certOwner);
        } else if (certOwner instanceof Service) {
            attrs = getAttributesService((Service) certOwner);
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
            switch(attrName) {
                case "callsign":
                    attrs.put(PKIConstants.MC_OID_CALLSIGN, attr.getAttributeValue());
                    break;
                case "imo-number":
                    attrs.put(PKIConstants.MC_OID_IMO_NUMBER, attr.getAttributeValue());
                    break;
                case "mmsi-number":
                    attrs.put(PKIConstants.MC_OID_MMSI_NUMBER, attr.getAttributeValue());
                    break;
                case "flagstate":
                    attrs.put(PKIConstants.MC_OID_FLAGSTATE, attr.getAttributeValue());
                    break;
                case "ais-class":
                    attrs.put(PKIConstants.MC_OID_AIS_SHIPTYPE, attr.getAttributeValue());
                    break;
                case "port-of-register":
                    attrs.put(PKIConstants.MC_OID_PORT_OF_REGISTER, attr.getAttributeValue());
                    break;
                default:
                    log.debug("Unexpected attribute value: " + attrName);
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
}
