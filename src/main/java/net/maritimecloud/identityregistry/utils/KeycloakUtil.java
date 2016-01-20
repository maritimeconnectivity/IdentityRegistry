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
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.util.JsonSerialization;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.NameValuePair;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

public class KeycloakUtil {
    @Value("${keycloak.configurationFile:WEB-INF/keycloak.json}")
    private Resource keycloakConfigFileResource;
    
    public static final String ERROR = "error";
    public static final String TOKEN = "token";
    public static final String TOKEN_PARSED = "idTokenParsed";
    public static final String REFRESH_TOKEN = "refreshToken";
    public static final String PRODUCTS = "products";
    public static final String CLIENT_AUTH_METHOD = "clientAuthMethod";
    private String token;
    private String refreshToken;
    private AccessToken tokenParsed;
    
    private ObjectMapper jsonMapper;

    public KeycloakUtil() {
        this.jsonMapper = new ObjectMapper();
    }

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

    private void setTokens(KeycloakDeployment deployment, AccessTokenResponse tokenResponse) throws IOException, VerificationException {
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
    
    public IdentityProviderRepresentation getIDP(AccessTokenResponse res) {

        CloseableHttpClient client = HttpClientBuilder.create().build();
        try {
            HttpGet get = new HttpGet("/admin/realms/{realm}/identity-provider/instances/{alias}");
            get.addHeader("Authorization", "Bearer " + res.getToken());
            try {
                HttpResponse response = client.execute(get);
                if (response.getStatusLine().getStatusCode() != 200) {
                    System.out.println(response.getStatusLine().getStatusCode());
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
    
    public void createIdentityProvider(String name, String wellKnownUrl, String clientId, String clientSecret) {
        // Get IDP info by parsing info from wellKnownUrl json
        URL url;
        try {
            url = new URL(wellKnownUrl);
        } catch (MalformedURLException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return;
        }
        HttpURLConnection request;
        try {
            request = (HttpURLConnection) url.openConnection();
            request.connect();
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return;
        }
        Map<String,Object> idpData;
        try {
            idpData = this.jsonMapper.readValue(new InputStreamReader((InputStream) request.getContent()), Map.class);
        } catch (JsonParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return;
        } catch (JsonMappingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return;
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return;
        }
        // Extract the endpoints from the json
        String authEndpoint = (String) idpData.get("authorization_endpoint");
        String tokenEndpoint = (String) idpData.get("token_endpoint");
        String userInfoEndpoint = (String) idpData.get("userinfo_endpoint");
        String endSessionEndpoint = (String) idpData.get("end_session_endpoint");
        String issuer = (String) idpData.get("issuer");
        
        // Insert data into IDP data structure
        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
        idp.setAlias(name);
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
        IDPConf.put("clientId", clientId);
        IDPConf.put("tokenUrl", tokenEndpoint);
        IDPConf.put("authorizationUrl", authEndpoint);
        IDPConf.put("logoutUrl", endSessionEndpoint);
        IDPConf.put("clientSecret", clientSecret);
        IDPConf.put("issuer", issuer);
        idp.setConfig(IDPConf);
        
        // Now POST the IDP data to keycloak 
        KeycloakDeployment deployment = getKeycloakDeployment();
        CloseableHttpClient client = HttpClientBuilder.create().build();

        try {
            HttpPost post = new HttpPost(deployment.getAuthServerBaseUrl() + "/admin/realms/master/identity-provider/instances");
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
        }
    }
    
    public void serviceAccountLogin() {
        KeycloakDeployment deployment = getKeycloakDeployment();
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
                setTokens(deployment, tokenResp);
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
            //req.setAttribute(ERROR, "Service account login failed. IOException occured. See server.log for details. Message is: " + ioe.getMessage());
        } catch (VerificationException vfe) {
            vfe.printStackTrace();
            //req.setAttribute(ERROR, "Service account login failed. Failed to verify token Message is: " + vfe.getMessage());
        }
    }
    
    public void getIDPs() {
        CloseableHttpClient client = HttpClientBuilder.create().build();

        HttpGet get = new HttpGet("http://localhost:9080" + "/auth/admin/realms/master/identity-provider/instances");
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
