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
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    // Load client template name used when creating clients in keycloak
    @Value("${net.maritimecloud.idreg.keycloak-client-template}")
    private String keycloakClientTemplate;

    // Type of user
    public static final int NORMAL_USER = 0;
    public static final int ADMIN_USER = 1;
    
    // Type of instance 
    public static final int BROKER_INSTANCE = 0;
    public static final int USER_INSTANCE = 1;

    private Keycloak keycloakBrokerInstance = null;
    private Keycloak keycloakUserInstance = null;

    private static final Logger logger = LoggerFactory.getLogger(KeycloakAdminUtil.class);

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
    
    private RealmResource getBrokerRealm() {
        return keycloakBrokerInstance.realm(keycloakBrokerRealm);
    }

    private RealmResource getProjectUserRealm() {
        return keycloakUserInstance.realm(keycloakProjectUsersRealm);
    }

    /**
     * Get IDP info by parsing info from wellKnownUrl json
     * 
     * @param wellKnownUrl The url to parse
     * @return  The IDP
     * @throws MalformedURLException
     * @throws IOException 
     */
    private IdentityProviderRepresentation getIdpFromWellKnownUrl(String wellKnownUrl) throws MalformedURLException, IOException {
        // Get IDP info by parsing info from wellKnownUrl json
        URL url;
        try {
            url = new URL(wellKnownUrl);
        } catch (MalformedURLException e1) {
            e1.printStackTrace();
            throw e1;
        }
        HttpURLConnection request;
        Map<String,Object> idpData;
        try {
            request = (HttpURLConnection) url.openConnection();
            request.connect();
            idpData = JsonSerialization.readValue((InputStream) request.getContent(), Map.class);
        } catch (IOException e1) {
            e1.printStackTrace();
            throw e1;
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
        idp.setFirstBrokerLoginFlowAlias("Auto first broker login");
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
     * @throws IOException 
     * @throws MalformedURLException 
     */
    public void createIdentityProvider(String name, String wellKnownUrl, String clientId, String clientSecret) throws MalformedURLException, IOException {
        // Get IDP info by parsing info from wellKnownUrl json
        IdentityProviderRepresentation idp = getIdpFromWellKnownUrl(wellKnownUrl);
        // Insert data into IDP data structure
        idp.setAlias(name);
        Map<String, String> IDPConf = idp.getConfig();
        IDPConf.put("clientId", clientId);
        IDPConf.put("clientSecret", clientSecret);
        idp.setConfig(IDPConf);
        
        // Check if the IDP already exists
        IdentityProviderResource oldIdpRes = getBrokerRealm().identityProviders().get(name);
        IdentityProviderRepresentation oldIdp = null;
        try {
            oldIdp = oldIdpRes.toRepresentation();
        } catch(NotFoundException nfe) {
        }
        if (oldIdp != null) {
            getBrokerRealm().identityProviders().get(name).update(idp);
        } else {
            getBrokerRealm().identityProviders().create(idp);
        }

        IdentityProviderResource newIdpRes = getBrokerRealm().identityProviders().get(name);
        // Create mappers - if they don't already exists
        ArrayList<String> mappers = new ArrayList<String>();
        for (IdentityProviderMapperRepresentation mapper : newIdpRes.getMappers()) {
            mappers.add(mapper.getName());
        }
        String orgMapperName = name + " org mapper";
        if (!mappers.contains(orgMapperName)) {
            // Create mapper for hardcoded org value
            IdentityProviderMapperRepresentation orgMapper = new IdentityProviderMapperRepresentation();
            orgMapper.setIdentityProviderAlias(name);
            orgMapper.setIdentityProviderMapper("hardcoded-attribute-idp-mapper");
            orgMapper.setName(orgMapperName);
            Map<String, String> orgMapperConf = new HashMap<String, String>();
            orgMapperConf.put("attribute.value", name);
            orgMapperConf.put("attribute", "org");
            orgMapper.setConfig(orgMapperConf);
            newIdpRes.addMapper(orgMapper);
        }

        String permissionMapperName = name + " permission mapper";
        if (!mappers.contains(permissionMapperName)) {
            // Create mapper for permissions attribute
            IdentityProviderMapperRepresentation permissionsMapper = new IdentityProviderMapperRepresentation();
            permissionsMapper.setIdentityProviderAlias(name);
            permissionsMapper.setIdentityProviderMapper("oidc-user-attribute-idp-mapper");
            permissionsMapper.setName(permissionMapperName);
            Map<String, String> permissionsMapperConf = new HashMap<String, String>();
            permissionsMapperConf.put("claim", "permissions");
            permissionsMapperConf.put("user.attribute", "permissions");
            permissionsMapper.setConfig(permissionsMapperConf);
            newIdpRes.addMapper(permissionsMapper);
        }

        String usernameMapperName = name + " username mapper";
        if (!mappers.contains(usernameMapperName)) {
            // Create mapper/template for username
            IdentityProviderMapperRepresentation usernameMapper = new IdentityProviderMapperRepresentation();
            usernameMapper.setIdentityProviderAlias(name);
            usernameMapper.setIdentityProviderMapper("oidc-username-idp-mapper");
            usernameMapper.setName(usernameMapperName);
            Map<String, String> usernameMapperConf = new HashMap<String, String>();
            usernameMapperConf.put("template", "${ALIAS}.${CLAIM.preferred_username}");
            usernameMapper.setConfig(usernameMapperConf);
            newIdpRes.addMapper(usernameMapper);
        }
    }
    
    /**
     * Delete Identity Provider with the given alias
     * 
     * @param alias  Alias of the IDP to delete.
     */
    public void deleteIdentityProvider(String alias) {
        getBrokerRealm().identityProviders().get(alias).remove();
    }
    
    private void getIDPs2() {
        IdentityProvidersResource idps2 =  getBrokerRealm().identityProviders();
        try {
            IdentityProviderRepresentation idp2 = idps2.get("toidp-asdfgh").toRepresentation();
            logger.debug(idp2.getAlias());
        } catch(NotFoundException nfe) {
        }
        
        List<IdentityProviderRepresentation> idps = idps2.findAll();
        for (IdentityProviderRepresentation idp : idps) {
            logger.debug(idp.getProviderId());
        }
        
        logger.debug(keycloakBrokerAdminUser + ", "  + keycloakBrokerAdminPassword + ", " + keycloakBrokerAdminClient);
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
     * @throws IOException 
     */
    public void createUser(String username, String password, String firstName, String lastName, String email, String orgShortName, boolean enabled, int userType) throws IOException {
        logger.debug("creating user: " + username);

        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEnabled(enabled);
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
            attr.put("permissions", Arrays.asList("MCADMIN,MCUSER"));
        } else if (userType == NORMAL_USER) {
            attr.put("permissions",  Arrays.asList("MCUSER"));
        }
        user.setAttributes(attr);
        Response ret = getProjectUserRealm().users().create(user);
        if (ret.getStatus() != 201) {
            logger.debug("creating user failed, status: " + ret.getStatus() + ", " + ret.readEntity(String.class));
            throw new IOException("User creation failed: " + ret.readEntity(String.class));
        }
        logger.debug("created user, status: " + ret.getStatus() + ", " + ret.readEntity(String.class));
        ret.close();
        
        // Set credentials
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setType(CredentialRepresentation.PASSWORD);
        cred.setValue(password);
        cred.setTemporary(false);
        // Find the user by searching for the username
        user = getProjectUserRealm().users().search(username, null, null, null, -1, -1).get(0);
        user.setCredentials(Arrays.asList(cred));
        logger.debug("setting password for user: " + user.getId());
        getProjectUserRealm().users().get(user.getId()).resetPassword(cred);
        logger.debug("created user");
    }


    /**
     * Updates the user in keycloak
     * 
     * @param username      username in keycloak. prefix with the (lowercase) org short name, like: dma.tgc
     * @param firstName     first name of user
     * @param lastName      last name of user
     * @param email         email of the user
     * @throws IOException 
     */
    public void updateUser(String username,  String firstName, String lastName, String email, boolean enabled) throws IOException {
        List<UserRepresentation> userReps = getProjectUserRealm().users().search(username, null, null, null, -1, -1);
        if (userReps.size() != 1) {
            logger.debug("Skipping user update! Found " + userReps.size() + " users while trying to update, expected 1");
            throw new IOException("User update failed! Found " + userReps.size() + " users while trying to update, expected 1");
        }
        UserRepresentation user = userReps.get(0);
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
            getProjectUserRealm().users().get(user.getId()).update(user);
        }
    }

    /**
     * Delete a user from Keycloak
     * 
     * @param username  username of the user to delete
     */
    public void deleteUser(String username) {
        // Find the user by searching for the username
        List<UserRepresentation> users = getProjectUserRealm().users().search(username, null, null, null, -1, -1);
        // If we found one, delete it
        if (!users.isEmpty()) {
            getProjectUserRealm().users().get(users.get(0).getId()).remove();
        }
    }

    /**
     * Creates an OpenId Connect client in keycloak
     *
     * @param clientId       The client id
     * @param type           The client type, can be public, bearer-only or confidential
     * @param redirectUri    The redirect uri
     * @return               Returns the generated client secret, unless the type is public, in which case an empty string is returned.
     * @throws IOException
     */
    public String createClient(String clientId, String type, String redirectUri) throws IOException {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(clientId);
        client.setClientAuthenticatorType("client-secret");
        client.setRedirectUris(Arrays.asList(redirectUri));
        client.setDirectAccessGrantsEnabled(false);
        client.setProtocol("openid-connect");
        client.setEnabled(true);
        client.setConsentRequired(false);
        client.setClientTemplate(keycloakClientTemplate); // the template includes the mappers needed
        if ("public".equals(type)) {
            client.setBearerOnly(false);
            client.setPublicClient(true);
        } else if ("bearer-only".equals(type)) {
            client.setBearerOnly(true);
            client.setPublicClient(false);
        } else {
            // Fallback to "confidential"
            client.setBearerOnly(false);
            client.setPublicClient(false);
        }
        // Create the client
        getBrokerRealm().clients().create(client);
        if (!"public".equals(type)) {
            // The client secret can't be retrived by the ClientRepresentation (bug?), so we need to use the ClientResource
            ClientRepresentation createdClient = getBrokerRealm().clients().findByClientId(clientId).get(0);
            String secret = getBrokerRealm().clients().get(createdClient.getId()).getSecret().getValue();
            return secret;
        } else {
            return "";
        }
    }

    /**
     * Updates an OpenId Connect client in keycloak
     *
     * @param clientId
     * @param type
     * @param redirectUri
     * @return               Returns the generated client secret, unless the type is public, in which case an empty string is returned.
     */
    public String updateClient(String clientId, String type, String redirectUri) {
        ClientRepresentation client = getBrokerRealm().clients().findByClientId(clientId).get(0);
        client.setClientAuthenticatorType(type);
        client.setRedirectUris(Arrays.asList(redirectUri));
        getBrokerRealm().clients().get(client.getId()).update(client);
        if (!type.equals("public")) {
            // The client secret can't be retrived by the ClientRepresentation (bug?), so we need to use the ClientResource
            String secret = getBrokerRealm().clients().get(client.getId()).getSecret().getValue();
            return secret;
        } else {
            return "";
        }
    }

    /**
     * Deletes an OpenId Connect client in keycloak
     *
     * @param clientId
     */
    public void deleteClient(String clientId) {
        ClientRepresentation client = getBrokerRealm().clients().findByClientId(clientId).get(0);
        getBrokerRealm().clients().get(client.getId()).remove();
    }

}
