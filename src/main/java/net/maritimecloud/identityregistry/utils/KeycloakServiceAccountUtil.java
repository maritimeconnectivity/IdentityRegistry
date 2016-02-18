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

import org.keycloak.OAuth2Constants;
import org.keycloak.RSATokenVerifier;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.authentication.ClientCredentialsProviderUtils;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.admin.client.resource.IdentityProvidersResource;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
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

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.NameValuePair;

public class KeycloakServiceAccountUtil {
    public static final String ERROR = "error";
    public static final String TOKEN = "token";
    public static final String TOKEN_PARSED = "idTokenParsed";
    public static final String REFRESH_TOKEN = "refreshToken";
    public static final String PRODUCTS = "products";
    public static final String CLIENT_AUTH_METHOD = "clientAuthMethod";
    private KeycloakDeployment deployment;
    private String token;
    private String refreshToken;
    private AccessToken tokenParsed;
    private String baseUrl;
    private String realm;
    private Keycloak keycloakInstance;

    
    
    /**
     * Constructor, loads KeycloakDeployment.
     */
    public KeycloakServiceAccountUtil() {
        this.deployment = this.getKeycloakDeployment();
        this.baseUrl = deployment.getAuthServerBaseUrl();
        this.realm = deployment.getRealm();
    }

    /**
     * Helper function to extract string from HttpEntity
     * 
     * @param entity
     * @return
     * @throws IOException
     */
    public static String getContent(HttpEntity entity) throws IOException {
        if (entity == null) return null;
        InputStream is = entity.getContent();
        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            int c;
            while ((c = is.read()) != -1) {
                os.write(c);
            }
            byte[] bytes = os.toByteArray();
            String data = new String(bytes);
            return data;
        } finally {
            try {
                is.close();
            } catch (IOException ignored) {
            }
        }
    }

    /**
     * Sets tokens after login
     * 
     * @param deployment
     * @param tokenResponse
     * @throws IOException
     * @throws VerificationException
     */
    private void setTokens(AccessTokenResponse tokenResponse) throws IOException, VerificationException {
        this.token = tokenResponse.getToken();
        this.refreshToken = tokenResponse.getRefreshToken();
        this.tokenParsed = RSATokenVerifier.verifyToken(token, deployment.getRealmKey(), deployment.getRealmInfoUrl());
    }

    /*private void refreshToken(HttpServletRequest req) {
        KeycloakDeployment deployment = getKeycloakDeployment();
        String refreshToken = (String) req.getSession().getAttribute(REFRESH_TOKEN);
        if (refreshToken == null) {
            req.setAttribute(ERROR, "No refresh token available. Please login first");
        } else {
            try {
                AccessTokenResponse tokenResponse = ServerRequest.invokeRefresh(deployment, refreshToken);
                setTokens(req, deployment, tokenResponse);
            } catch (ServerRequest.HttpFailure hfe) {
                hfe.printStackTrace();
                req.setAttribute(ERROR, "Failed refresh token. See server.log for details. Status was: " + hfe.getStatus() + ", Error is: " + hfe.getError());
            } catch (Exception ioe) {
                ioe.printStackTrace();
                req.setAttribute(ERROR, "Failed refresh token. See server.log for details. Message is: " + ioe.getMessage());
            }
        }
    }

    private void logout(HttpServletRequest req) {
        KeycloakDeployment deployment = getKeycloakDeployment();
        String refreshToken = (String) req.getSession().getAttribute(REFRESH_TOKEN);
        if (refreshToken == null) {
            req.setAttribute(ERROR, "No refresh token available. Please login first");
        } else {
            try {
                ServerRequest.invokeLogout(deployment, refreshToken);
                req.getSession().removeAttribute(TOKEN);
                req.getSession().removeAttribute(REFRESH_TOKEN);
                req.getSession().removeAttribute(TOKEN_PARSED);
            } catch (IOException ioe) {
                ioe.printStackTrace();
                req.setAttribute(ERROR, "Failed refresh token. See server.log for details. Message is: " + ioe.getMessage());
            } catch (ServerRequest.HttpFailure hfe) {
                hfe.printStackTrace();
                req.setAttribute(ERROR, "Failed refresh token. See server.log for details. Status was: " + hfe.getStatus() + ", Error is: " + hfe.getError());
            }
        }
    }*/
    
    /**
     * Fetches and returns data on an IDP
     * 
     * @param name   name of the IDP
     * @return
     */
    public IdentityProviderRepresentation getIDP(String name) {
        CloseableHttpClient client = HttpClientBuilder.create().build();
        try {
            HttpGet get = new HttpGet(baseUrl + "/admin/realms/" + realm + "/identity-provider/instances/" + name);
            get.addHeader("Authorization", "Bearer " + token);
            try {
                HttpResponse response = client.execute(get);
                if (response.getStatusLine().getStatusCode() != 200) {
                    System.out.println(response.getStatusLine().getStatusCode());
                    return null;
                }
                HttpEntity entity = response.getEntity();
                InputStream is = entity.getContent();
                try {
                    return JsonSerialization.readValue(is, IdentityProviderRepresentation.class);
                } finally {
                    is.close();
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } finally {
            try {
                client.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }
    
    /**
     * Get IDP info by parsing info from wellKnownUrl json
     * 
     * @param wellKnownUrl The url to parse
     * @return
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
            //idpData = this.jsonMapper.readValue(new InputStreamReader((InputStream) request.getContent()), Map.class);
            idpData = JsonSerialization.readValue((InputStream) request.getContent(), Map.class);
        /*} catch (JsonParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        } catch (JsonMappingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;*/
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
        IdentityProviderRepresentation oldIdp = null;
        try {
            oldIdp = this.getIDP(clientId);
        } catch (Exception e) {
        }
        
        CloseableHttpClient client = HttpClientBuilder.create().build();
        // If the IDP already exists, update it, otherwise create it.
        if (oldIdp == null) {
            // Now POST the IDP data to keycloak 
            try {
                HttpPost post = new HttpPost(deployment.getAuthServerBaseUrl() + "/admin/realms/" + realm + "/identity-provider/instances");
                if (token != null) {
                    post.addHeader("Authorization", "Bearer " + token);
                }
                System.out.println("idp creating json: " + JsonSerialization.writeValueAsString(idp));
                StringEntity input = new StringEntity(JsonSerialization.writeValueAsString(idp));
                input.setContentType("application/json");
                post.setEntity(input);
                HttpResponse response = client.execute(post);
                int status = response.getStatusLine().getStatusCode();
                HttpEntity entity = response.getEntity();
                if (status != 201) {
                    String json = getContent(entity);
                    String error = "IDP creation failed. Bad status: " + status + " response: " + json;
                    System.out.println(error);
                    //req.setAttribute(ERROR, error);
                } else {
                    System.out.println("IDP created! " + getContent(entity));
                }
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        } else {
            // Now PUT the IDP data to keycloak 
            try {
                HttpPut put = new HttpPut(deployment.getAuthServerBaseUrl() + "/admin/realms/" + realm + "/identity-provider/instances/" + clientId);
                if (token != null) {
                    put.addHeader("Authorization", "Bearer " + token);
                }
                System.out.println("idp update json: " + JsonSerialization.writeValueAsString(idp));
                StringEntity input = new StringEntity(JsonSerialization.writeValueAsString(idp));
                input.setContentType("application/json");
                put.setEntity(input);
                HttpResponse response = client.execute(put);
                int status = response.getStatusLine().getStatusCode();
                HttpEntity entity = response.getEntity();
                if (status != 201) {
                    String json = getContent(entity);
                    String error = "IDP update failed. Bad status: " + status + " response: " + json;
                    System.out.println(error);
                    //req.setAttribute(ERROR, error);
                } else {
                    System.out.println("IDP updated! " + getContent(entity));
                }
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }
    }
    
    /**
     * Use the clientId in the loaded KeycloakDeployment to log in to Keycloak using a service account.
     * Copied from Keycloaks service-account example and modified to fit in.
     */
    public void serviceAccountLogin() {
        CloseableHttpClient client = HttpClientBuilder.create().build();

        try {
            HttpPost post = new HttpPost(deployment.getTokenUrl());
            List<NameValuePair> formparams = new ArrayList<NameValuePair>();
            formparams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.CLIENT_CREDENTIALS));

            // Add client credentials according to the method configured in keycloak-client-secret.json or keycloak-client-signed-jwt.json file
            Map<String, String> reqHeaders = new HashMap<>();
            Map<String, String> reqParams = new HashMap<>();
            ClientCredentialsProviderUtils.setClientCredentials(deployment, reqHeaders, reqParams);
            for (Map.Entry<String, String> header : reqHeaders.entrySet()) {
                post.setHeader(header.getKey(), header.getValue());
            }
            for (Map.Entry<String, String> param : reqParams.entrySet()) {
                formparams.add(new BasicNameValuePair(param.getKey(), param.getValue()));
            }

            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);

            HttpResponse response = client.execute(post);
            int status = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (status != 200) {
                String json = getContent(entity);
                String error = "Service account login failed. Bad status: " + status + " response: " + json;
                //req.setAttribute(ERROR, error);
            } else if (entity == null) {
                //req.setAttribute(ERROR, "No entity");
            } else {
                String json = getContent(entity);
                AccessTokenResponse tokenResp = JsonSerialization.readValue(json, AccessTokenResponse.class);
                setTokens(tokenResp);
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
            //req.setAttribute(ERROR, "Service account login failed. IOException occured. See server.log for details. Message is: " + ioe.getMessage());
        } catch (VerificationException vfe) {
            vfe.printStackTrace();
            //req.setAttribute(ERROR, "Service account login failed. Failed to verify token Message is: " + vfe.getMessage());
        }
    }
    
    
    /**
     * Gets and prints a list of the IDPs available in the keycloak instance.
     */
    public void getIDPs() {
        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(baseUrl + "/auth/admin/realms/" + realm + "/identity-provider/instances");
        if (token != null) {
            get.addHeader("Authorization", "Bearer " + token);
        }
        try {
            HttpResponse response = client.execute(get);
            HttpEntity entity = response.getEntity();
            int status = response.getStatusLine().getStatusCode();
            if (status != 200) {
                String json = getContent(entity);
                String error = "Failed retrieve IDPs. Status: " + status;
                System.out.println(error);
                //req.setAttribute(ERROR, error);
            } else if (entity == null) {
                System.out.println("No entity");
                //req.setAttribute(ERROR, "No entity");
            } else {
                String idps = getContent(entity);
                System.out.println("IDPs: " + idps);
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
            //req.setAttribute(ERROR, "Failed retrieve products. IOException occured. See server.log for details. Message is: " + ioe.getMessage());
        }
    }

    /**
     * Deletes the IDP identified by the given name.
     * 
     * @param name    the IDP to be deleted.
     */
    public void deleteIDP(String name) {
        CloseableHttpClient client = HttpClientBuilder.create().build();
        HttpDelete delete = new HttpDelete(baseUrl + "/auth/admin/realms/" + realm + "/identity-provider/instances/" + name);
        if (token != null) {
            delete.addHeader("Authorization", "Bearer " + token);
        }
        try {
            HttpResponse response = client.execute(delete);
            HttpEntity entity = response.getEntity();
            int status = response.getStatusLine().getStatusCode();
            if (status != 200 && status != 204) {
                String json = getContent(entity);
                String error = "Failed deleting IDP. Status: " + status + ", content: " + json;
                System.out.println(error);
                //req.setAttribute(ERROR, error);
            } else {
                System.out.println("Deleted IDP " + name);
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
            //req.setAttribute(ERROR, "Failed retrieve products. IOException occured. See server.log for details. Message is: " + ioe.getMessage());
        }
    }

    public void createUser(String name, String password, String email, String orgShortName) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(name);
        user.setEnabled(true);
        if (email != null && !email.trim().isEmpty()) {
            user.setEmail(email);
            user.setEmailVerified(true);
        }
        // Set roles for the MD identity register - the clientId of the portal should be updated as needed!
        /*HashMap<String, List<String>> clientRoles = new HashMap<String, List<String>>();
        String clientId = "mcregportal"; //deployment.getResourceCredentials().keySet().iterator().next();
        clientRoles.put(clientId, Arrays.asList("ROLE_ADMIN"));
        user.setClientRoles(clientRoles);*/
        
        // Set attributes
        Map<String, Object> attr = new HashMap<String,Object>();
        attr.put("org", orgShortName);
        attr.put("permissions", "MCADMIN");
        user.setAttributes(attr);
        
        // Set credentials
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setType(CredentialRepresentation.PASSWORD);
        cred.setValue(password);
        user.setCredentials(Arrays.asList(cred));
        
        // Now POST the IDP data to keycloak 
        CloseableHttpClient client = HttpClientBuilder.create().build();
        try {
            HttpPost post = new HttpPost(deployment.getAuthServerBaseUrl() + "/admin/realms/" + realm + "/users");
            if (token != null) {
                post.addHeader("Authorization", "Bearer " + token);
            }
            System.out.println("user creating json: " + JsonSerialization.writeValueAsString(user));
            StringEntity input = new StringEntity(JsonSerialization.writeValueAsString(user));
            input.setContentType("application/json");
            post.setEntity(input);
            HttpResponse response = client.execute(post);
            int status = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (status != 201) {
                String json = getContent(entity);
                String error = "IDP creation failed. Bad status: " + status + " response: " + json;
                System.out.println(error);
                //req.setAttribute(ERROR, error);
            } else {
                System.out.println("IDP created! " + getContent(entity));
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    /**
     * Load a KeycloakDeployment instance from "WEB-INF/keycloak.json" and returns it
     * 
     * @return The loaded KeycloakDeployment instance.
     */
    private KeycloakDeployment getKeycloakDeployment() {
        try {
            Resource resource = new ClassPathResource("WEB-INF/keycloak.json");
            return KeycloakDeploymentBuilder.build(resource.getInputStream());
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }
}
