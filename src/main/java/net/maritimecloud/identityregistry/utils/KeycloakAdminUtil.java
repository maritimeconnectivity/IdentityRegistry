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
package net.maritimecloud.identityregistry.utils;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.admin.client.resource.IdentityProvidersResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;

@Component
public class KeycloakAdminUtil {
    // Load the info needed to log into the Keycloak instance that is used as ID Broker (hosts ID Providers) 
    @Value("${net.maritimecloud.idreg.keycloak-broker-admin-user}")
    private String keycloakBrokerAdminUser;
    @Value("${net.maritimecloud.idreg.keycloak-broker-admin-password}")
    private String keycloakBrokerAdminPassword;
    @Value("${net.maritimecloud.idreg.keycloak-broker-admin-client}")
    private String keycloakBrokerAdminClient;
    @Value("${net.maritimecloud.idreg.keycloak-broker-realm}")
    private String keycloakBrokerRealm;
    @Value("${net.maritimecloud.idreg.keycloak-broker-base-url}")
    private String keycloakBrokerBaseUrl;

    // Load the info needed to log into the Keycloak instance that is used as to host project users
    @Value("${net.maritimecloud.idreg.keycloak-project-users-admin-user}")
    private String keycloakProjectUsersAdminUser;
    @Value("${net.maritimecloud.idreg.keycloak-project-users-admin-password}")
    private String keycloakProjectUsersAdminPassword;
    @Value("${net.maritimecloud.idreg.keycloak-project-users-admin-client}")
    private String keycloakProjectUsersAdminClient;
    @Value("${net.maritimecloud.idreg.keycloak-project-users-realm}")
    private String keycloakProjectUsersRealm;
    @Value("${net.maritimecloud.idreg.keycloak-project-users-base-url}")
    private String keycloakProjectUsersBaseUrl;

    // Type of user
    public static final int NORMAL_USER = 0;
    public static final int ADMIN_USER = 1;
    
    // Type of instance 
    public static final int BROKER_INSTANCE = 0;
    public static final int USER_INSTANCE = 1;

    private Keycloak keycloakBrokerInstance = null;
    private Keycloak keycloakUserInstance = null;
    
    /**
     * Constructor.
     */
    public KeycloakAdminUtil() {
    }

    /**
     * Init the keycloak instance. Will only initialize the instance defined by the type
     * 
     * @param type  The type of instance to initialize.
     */
    public void init(int type) {
        //keycloakInstance = Keycloak.getInstance(deployment.getAuthServerBaseUrl(), deployment.getRealm(), "idreg-admin", "idreg-admin", "mcidreg", "1b1f1686-1391-4b25-b770-906a2ffc7db9");
        //keycloakInstance = Keycloak.getInstance(keycloakBaseUrl, keycloakRealm, "idreg-admin", "idreg-admin", "security-admin-console");
        if (type == BROKER_INSTANCE) {
            keycloakBrokerInstance = Keycloak.getInstance(keycloakBrokerBaseUrl, keycloakBrokerRealm, keycloakBrokerAdminUser, keycloakBrokerAdminPassword, keycloakBrokerAdminClient);
        } else if (type == USER_INSTANCE) {
            keycloakUserInstance = Keycloak.getInstance(keycloakProjectUsersBaseUrl, keycloakProjectUsersRealm, keycloakProjectUsersAdminUser, keycloakProjectUsersAdminPassword, keycloakProjectUsersAdminClient);
        }
    }
    
    /**
     * Get IDP info by parsing info from wellKnownUrl json
     * 
     * @param wellKnownUrl The url to parse
     * @return  The IDP
     */
    private IdentityProviderRepresentation getIdpFromWellKnownUrl(String wellKnownUrl) {
        // Get IDP info by parsing info from wellKnownUrl json
        URL url;
        try {
            url = new URL(wellKnownUrl);
        } catch (MalformedURLException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        }
        HttpURLConnection request;
        try {
            request = (HttpURLConnection) url.openConnection();
            request.connect();
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        }
        Map<String,Object> idpData;
        try {
            idpData = JsonSerialization.readValue((InputStream) request.getContent(), Map.class);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
        // Extract the endpoints from the json
        String authEndpoint = (String) idpData.get("authorization_endpoint");
        String tokenEndpoint = (String) idpData.get("token_endpoint");
        String userInfoEndpoint = (String) idpData.get("userinfo_endpoint");
        String endSessionEndpoint = (String) idpData.get("end_session_endpoint");
        String issuer = (String) idpData.get("issuer");
        
        // Insert data into IDP data structure
        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
        idp.setEnabled(true);
        idp.setProviderId("keycloak-oidc"); // can be "keycloak-oidc","oidc" or "saml"
        idp.setTrustEmail(false);
        idp.setStoreToken(false);
        idp.setAddReadTokenRoleOnCreate(false);
        idp.setAuthenticateByDefault(false);
        idp.setFirstBrokerLoginFlowAlias("first broker login");
        Map<String, String> IDPConf = new HashMap<String, String>();
        IDPConf.put("userInfoUrl", userInfoEndpoint);
        IDPConf.put("validateSignature", "true");
        IDPConf.put("tokenUrl", tokenEndpoint);
        IDPConf.put("authorizationUrl", authEndpoint);
        IDPConf.put("logoutUrl", endSessionEndpoint);
        IDPConf.put("issuer", issuer);
        idp.setConfig(IDPConf);
        return idp;
    }
    
    /**
     * Creates or updates an IDP.
     * 
     * @param name          name of the IDP
     * @param wellKnownUrl  the url where info on the IDP can be obtained
     * @param clientId      the id used for the MC in the IDP
     * @param clientSecret  the secret used for the MC in the IDP
     */
    public void createIdentityProvider(String name, String wellKnownUrl, String clientId, String clientSecret) {
        // Get IDP info by parsing info from wellKnownUrl json
        IdentityProviderRepresentation idp = getIdpFromWellKnownUrl(wellKnownUrl);
        if (idp == null) {
            return;
        }
        // Insert data into IDP data structure
        idp.setAlias(name);
        Map<String, String> IDPConf = idp.getConfig();
        IDPConf.put("clientId", clientId);
        IDPConf.put("clientSecret", clientSecret);
        idp.setConfig(IDPConf);
        
        // Check if the IDP already exists
        IdentityProviderResource oldIdpRes = keycloakBrokerInstance.realm(keycloakBrokerRealm).identityProviders().get(name);
        IdentityProviderRepresentation oldIdp = null;
        try {
            oldIdp = oldIdpRes.toRepresentation();
        } catch(NotFoundException nfe) {
        }
        if (oldIdp != null) {
            keycloakBrokerInstance.realm(keycloakBrokerRealm).identityProviders().get(name).update(idp);
        } else {
            keycloakBrokerInstance.realm(keycloakBrokerRealm).identityProviders().create(idp);
        }
    }
    
    /**
     * Delete Identity Provider with the given alias
     * 
     * @param alias  Alias of the IDP to delete.
     */
    public void deleteIdentityProvider(String alias) {
        keycloakBrokerInstance.realm(keycloakBrokerRealm).identityProviders().get(alias).remove();
    }
    
    private void getIDPs2() {
        IdentityProvidersResource idps2 =  keycloakBrokerInstance.realm(keycloakBrokerRealm).identityProviders();
        try {
            IdentityProviderRepresentation idp2 = idps2.get("toidp-asdfgh").toRepresentation();
            System.out.println(idp2.getAlias());
        } catch(NotFoundException nfe) {
        }
        
        List<IdentityProviderRepresentation> idps = idps2.findAll();
        for (IdentityProviderRepresentation idp : idps) {
            System.out.println(idp.getProviderId());
        }
        
        System.out.println(keycloakBrokerAdminUser + ", "  + keycloakBrokerAdminPassword + ", " + keycloakBrokerAdminClient);
    }


    /**
     * Creates a user in keycloak.
     * 
     * @param username      username in keycloak. prefix with the (lowercase) org short name, like: dma.tgc
     * @param firstName     first name of user
     * @param lastName      last name of user
     * @param password      password of the user
     * @param email         email of the user
     * @param orgShortName  shortname of the org
     * @param userType      type of user, determines rights.
     */
    public void createUser(String username, String password, String firstName, String lastName, String email, String orgShortName, int userType) {
        System.out.println("creating user: " + username);

        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEnabled(true);
        if (email != null && !email.trim().isEmpty()) {
            user.setEmail(email);
            user.setEmailVerified(true);
        }
        if (firstName != null && !firstName.trim().isEmpty()) {
            user.setFirstName(firstName);
        }
        if (lastName != null && !lastName.trim().isEmpty()) {
            user.setLastName(lastName);
        }
        // Set attributes
        Map<String, Object> attr = new HashMap<String,Object>();
        attr.put("org", Arrays.asList(orgShortName));
        if (userType == ADMIN_USER) {
            attr.put("permissions", Arrays.asList("MCADMIN", "MCUSER"));
        } else if (userType == NORMAL_USER) {
            attr.put("permissions", Arrays.asList("MCUSER"));
        }
        user.setAttributes(attr);
        Response ret = keycloakUserInstance.realm(keycloakBrokerRealm).users().create(user);
        if (ret.getStatus() != 201) {
            System.out.println("creating user failed, status: " + ret.getStatus() + ", " + ret.readEntity(String.class));
            return;
        }
        System.out.println("created user, status: " + ret.getStatus() + ", " + ret.readEntity(String.class));
        ret.close();
        
        // Set credentials
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setType(CredentialRepresentation.PASSWORD);
        cred.setValue(password);
        cred.setTemporary(false);
        // Find the user by searching for the username
        user = keycloakUserInstance.realm(keycloakBrokerRealm).users().search(username, null, null, null, -1, -1).get(0);
        user.setCredentials(Arrays.asList(cred));
        System.out.println("setting password for user: " + user.getId());
        keycloakUserInstance.realm(keycloakBrokerRealm).users().get(user.getId()).resetPassword(cred);
        System.out.println("created user");
    }


    /**
     * Updates the user in keycloak
     * 
     * @param username      username in keycloak. prefix with the (lowercase) org short name, like: dma.tgc
     * @param firstName     first name of user
     * @param lastName      last name of user
     * @param email         email of the user
     */
    public void updateUser(String username,  String firstName, String lastName, String email) {
        UserRepresentation user = keycloakUserInstance.realm(keycloakBrokerRealm).users().search(username, null, null, null, -1, -1).get(0);
        boolean updated = false;
        if (email != null && !email.trim().isEmpty()) {
            user.setEmail(email);
            user.setEmailVerified(true);
            updated = true;
        }
        if (firstName != null && !firstName.trim().isEmpty()) {
            user.setFirstName(firstName);
            updated = true;
        }
        if (lastName != null && !lastName.trim().isEmpty()) {
            user.setLastName(lastName);
            updated = true;
        }
        if (updated) {
            keycloakUserInstance.realm(keycloakBrokerRealm).users().get(user.getId()).update(user);
        }
    }


    /**
     * Delete a user from Keycloak
     * 
     * @param username  username of the user to delete
     */
    public void deleteUser(String username) {
        // Find the user by searching for the username
        List<UserRepresentation> users = keycloakUserInstance.realm(keycloakBrokerRealm).users().search(username, null, null, null, -1, -1);
        // If we found one, delete it
        if (!users.isEmpty()) {
            keycloakUserInstance.realm(keycloakBrokerRealm).users().get(users.get(0).getId()).remove();
        }
    }
}
