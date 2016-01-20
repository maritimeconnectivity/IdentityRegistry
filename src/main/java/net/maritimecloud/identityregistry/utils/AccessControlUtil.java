package net.maritimecloud.identityregistry.utils;

import java.util.Map;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class AccessControlUtil {

    public static final String ORG_PROPERTY_NAME = "org";
    
    public static boolean hasAccessToOrg(String orgName) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof KeycloakAuthenticationToken) {
            KeycloakAuthenticationToken kat = (KeycloakAuthenticationToken) auth;
            KeycloakSecurityContext ksc = (KeycloakSecurityContext)kat.getCredentials();
            Map<String, Object> otherClaims = ksc.getToken().getOtherClaims();
            if (otherClaims.containsKey(AccessControlUtil.ORG_PROPERTY_NAME) &&
                    ((String)otherClaims.get(AccessControlUtil.ORG_PROPERTY_NAME)).toLowerCase().equals(orgName.toLowerCase())) {
                return true;
            }
        } else if (auth instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken upat = (UsernamePasswordAuthenticationToken) auth;
            if (upat.getName().equals(orgName)) {
                return true;
            }
        } else {
            System.out.println(auth.getClass());
        }

        
        return false;
    }
}
