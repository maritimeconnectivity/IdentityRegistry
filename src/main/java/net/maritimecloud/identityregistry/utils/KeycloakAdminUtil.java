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

import net.maritimecloud.identityregistry.model.database.IdentityProviderAttribute;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.admin.client.resource.IdentityProvidersResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
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
import java.nio.charset.MalformedInputException;
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
     * @param infoUrl The url to parse
     * @param providerId The provider type, can be "keycloak-oidc","oidc" or "saml"
     * @return  The IDP
     * @throws IOException
     */
    private Map<String, String> getIdpSetupUrl(String infoUrl, String providerId) throws IOException {
        // Get IDP info by using keycloaks builtin parser
        Map<String, Object> importFromUrl = new HashMap<String, Object>();
        importFromUrl.put("fromUrl", infoUrl);
        importFromUrl.put("providerId", providerId); // providerId can be either "keycloak-oidc", "oidc" or "saml"
        Map<String, String> importConf = getBrokerRealm().identityProviders().importFrom(importFromUrl);
        // Do some checks to validate the returned
        if (importConf == null || importConf.isEmpty()) {
            throw new IOException("Could not find needed information using the provided URL!");
        }
        return importConf;
    }

    private Map<String, String> idpAttributes2Map(List<IdentityProviderAttribute> input) {
        logger.debug("In idpAttributes2Map, number of attrs: " + input.size());
        Map<String, String> ret = new HashMap<>();
        for (IdentityProviderAttribute atr : input) {
            ret.put(atr.getAttributeName(), atr.getAttributeValue());
            logger.debug("idp attr name: " + atr.getAttributeName()+ ", value: " + atr.getAttributeValue());
        }
        return ret;
    }

    /**
     * Creates or updates an IDP.
     * 
     * @param name          name of the IDP
     * @param input         map containing data about the IDP
     * @throws IOException
     */
    public void createIdentityProvider(String name, List<IdentityProviderAttribute> input) throws IOException {
        Map<String, String> idpAtrMap = idpAttributes2Map(input);
        // Check for valid input
        String providerType = idpAtrMap.get("providerType");
        if (providerType == null || providerType.isEmpty()) {
            throw new IllegalArgumentException("Missing providerType");
        }
        if (!"oidc".equals(providerType) && !"saml".equals(providerType)) {
            throw new IllegalArgumentException("Illegal providerType, must be \"oidc\" or \"saml\"");
        }
        // Get data from URL if supplied
        Map<String, String> importConf;
        if (idpAtrMap.containsKey("importUrl")) {
            importConf = getIdpSetupUrl(idpAtrMap.get("importUrl"), idpAtrMap.get("providerType"));
        } else {
            importConf = new HashMap<String, String>(idpAtrMap);
            importConf.remove("providerType");
        }
        if ("oidc".equals(providerType)) {
            // Check for valid input
            String clientId = idpAtrMap.get("clientId");
            String clientSecret = idpAtrMap.get("clientSecret");
            if (clientId == null || clientId.isEmpty()) {
                throw new IllegalArgumentException("Missing clientId");
            }
            if (clientSecret == null || clientSecret.isEmpty()) {
                throw new IllegalArgumentException("Missing clientSecret");
            }

            importConf.put("clientId", clientId);
            importConf.put("clientSecret", clientSecret);
        }
        // Insert data into IDP data structure
        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
        idp.setAlias(name);
        idp.setEnabled(true);
        idp.setProviderId(providerType); // can be "keycloak-oidc","oidc" or "saml"
        idp.setTrustEmail(true);
        idp.setStoreToken(false);
        idp.setAddReadTokenRoleOnCreate(false);
        idp.setAuthenticateByDefault(false);
        idp.setFirstBrokerLoginFlowAlias("Auto first broker login");
        idp.setConfig(importConf);

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
            Response ret = getBrokerRealm().identityProviders().create(idp);
            logger.debug("Returned status from creating IDP: " + ret.getStatus());
            if (ret.getStatus() != 201) {
                throw new IOException("Could not create IDP");
            }
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
        // First delete any users associated with the IDP
        List<UserRepresentation> users = getBrokerRealm().users().search(/* username*/ alias + ".", /* firstName */ null, /* lastName */ null, /* email */ null,  /* first */ 0, /* max*/ 0);
        for (UserRepresentation user : users) {
            if (user.getUsername().startsWith(alias + ".")) {
                getBrokerRealm().users().get(user.getId()).remove();
            }
        }
        // Delete IDP
        getBrokerRealm().identityProviders().get(alias).remove();
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
    public void createUser(String username, String password, String firstName, String lastName, String email, String orgShortName, String permissions, boolean enabled, int userType) throws IOException {
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
            attr.put("permissions", Arrays.asList(permissions));
        } else if (userType == NORMAL_USER) {
            attr.put("permissions",  Arrays.asList(permissions));
        }
        user.setAttributes(attr);
        Response ret;
        if (userType == ADMIN_USER) {
            ret = getBrokerRealm().users().create(user);
        } else {
            ret = getProjectUserRealm().users().create(user);
        }
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
        if (userType == ADMIN_USER) {
            user = getBrokerRealm().users().search(username, null, null, null, -1, -1).get(0);
        } else {
            user = getProjectUserRealm().users().search(username, null, null, null, -1, -1).get(0);
        }
        user.setCredentials(Arrays.asList(cred));
        logger.debug("setting password for user: " + user.getId());
        if (userType == ADMIN_USER) {
            getBrokerRealm().users().get(user.getId()).resetPassword(cred);
        } else {
            getProjectUserRealm().users().get(user.getId()).resetPassword(cred);
        }
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
    public void updateUser(String username,  String firstName, String lastName, String email, String newPermissions, boolean enabled) throws IOException {
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
        Map<String, Object> attr = user.getAttributes();
        if (attr.containsKey("permissions")) {
            List<String> oldPermissions = (List<String>) attr.get("permissions");
            if (oldPermissions != null && !oldPermissions.isEmpty()) {
                String permission = oldPermissions.get(0);
                if (permission == null || !permission.equals(newPermissions)) {
                    attr.put("permissions", Arrays.asList(newPermissions));
                    user.setAttributes(attr);
                    updated = true;
                }
            }
        } else {
            if (newPermissions != null) {
                attr.put("permissions", Arrays.asList(newPermissions));
                user.setAttributes(attr);
                updated = true;
            }
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
