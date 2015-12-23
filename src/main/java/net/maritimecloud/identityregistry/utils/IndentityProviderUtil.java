/* Copyright 2015 Danish Maritime Authority.
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
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.util.JsonSerialization;
import org.springframework.beans.factory.annotation.Value;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.NameValuePair;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

public class IndentityProviderUtil {
    
    private String name;
    
    private String wellKnownUrl;

    private String clientId;
    
    private String clientSecret;
    
    private ObjectMapper jsonMapper;
    
    @Value("${maritimecloud.identitybroker.baseurl}")
    private String IDBBaseUrl;
    
    @Value("${maritimecloud.identitybroker.clientid}")
    private String IDBClientId;

    @Value("${maritimecloud.identitybroker.clientsecret}")
    private String IDBClientSecret;

    IndentityProviderUtil(String name, String wellKnownUrl, String clientId, String clientSecret) {
        this.wellKnownUrl = wellKnownUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.jsonMapper = new ObjectMapper();
    }

    public static class Failure extends Exception {
        private int status;

        public Failure(int status) {
            this.status = status;
        }

        public int getStatus() {
            return status;
        }
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

    public AccessTokenResponse getToken() throws IOException {

        CloseableHttpClient client = HttpClientBuilder.create().build();


        try {
            HttpPost post = new HttpPost(KeycloakUriBuilder.fromUri(this.IDBBaseUrl)
                    .path(ServiceUrlConstants.TOKEN_PATH).build("demo"));
            List <NameValuePair> formparams = new ArrayList <NameValuePair>();
            formparams.add(new BasicNameValuePair("username", this.IDBClientId));
            formparams.add(new BasicNameValuePair("password", this.IDBClientSecret));
            formparams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, "password"));
            formparams.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, "admin-client"));
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);

            HttpResponse response = client.execute(post);
            int status = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (status != 200) {
                String json = getContent(entity);
                throw new IOException("Bad status: " + status + " response: " + json);
            }
            if (entity == null) {
                throw new IOException("No Entity");
            }
            String json = getContent(entity);
            return JsonSerialization.readValue(json, AccessTokenResponse.class);
        } finally {
            client.close();
        }
    }

    public void logout(AccessTokenResponse res) throws IOException {

        CloseableHttpClient client = HttpClientBuilder.create().build();


        try {
            HttpPost post = new HttpPost(KeycloakUriBuilder.fromUri(this.IDBBaseUrl)
                    .path(ServiceUrlConstants.TOKEN_SERVICE_LOGOUT_PATH)
                    .build("demo"));
            List<NameValuePair> formparams = new ArrayList<NameValuePair>();
            formparams.add(new BasicNameValuePair(OAuth2Constants.REFRESH_TOKEN, res.getRefreshToken()));
            formparams.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, "admin-client"));
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);
            HttpResponse response = client.execute(post);
            boolean status = response.getStatusLine().getStatusCode() != 204;
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                return;
            }
            InputStream is = entity.getContent();
            if (is != null) is.close();
            if (status) {
                throw new RuntimeException("failed to logout");
            }
        } finally {
            client.close();
        }
    }
    
    public IdentityProviderRepresentation getIDP(AccessTokenResponse res) throws Failure {

        CloseableHttpClient client = HttpClientBuilder.create().build();
        try {
            HttpGet get = new HttpGet(this.IDBBaseUrl + "/admin/realms/{realm}/identity-provider/instances/{alias}");
            get.addHeader("Authorization", "Bearer " + res.getToken());
            try {
                HttpResponse response = client.execute(get);
                if (response.getStatusLine().getStatusCode() != 200) {
                    throw new Failure(response.getStatusLine().getStatusCode());
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
    
    public void createIdentityProvider() {
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
        String authEndpoint = (String) idpData.get("authorization_endpoint");
        String tokenEndpoint = (String) idpData.get("token_endpoint");
        
        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
        idp.setAlias(this.name);
        
    }
    
    public String getWellKnownUrl() {
        return wellKnownUrl;
    }

    public void setWellKnownUrl(String wellKnownUrl) {
        this.wellKnownUrl = wellKnownUrl;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIDBBaseUrl() {
        return IDBBaseUrl;
    }

    public void setIDBBaseUrl(String iDBBaseUrl) {
        IDBBaseUrl = iDBBaseUrl;
    }

    public String getIDBClientId() {
        return IDBClientId;
    }

    public void setIDBClientId(String iDBClientId) {
        IDBClientId = iDBClientId;
    }

    public String getIDBClientSecret() {
        return IDBClientSecret;
    }

    public void setIDBClientSecret(String iDBClientSecret) {
        IDBClientSecret = iDBClientSecret;
    }
}
