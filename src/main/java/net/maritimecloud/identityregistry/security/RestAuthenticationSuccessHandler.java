/*
 * Copyright (C) 2014 The Climate Corporation and released under an Apache 2.0 license.
 * You may not use this library except in compliance with the License.
 * You may obtain a copy of the License at:

 * http://www.apache.org/licenses/LICENSE-2.0

 * See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */

package net.maritimecloud.identityregistry.security;
//package com.climate.oada.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

/**
 * By default, form login will answer a successful authentication request with a 301 MOVED PERMANENTLY status code; this makes sense
 * in the context of an actual login form which needs to redirect after login. For a RESTful web service however, the desired
 * response for a successful authentication should be 200 OK.
 *
 * This is done by injecting a custom authentication success handler in the form login filter, to replace the default one. The new
 * handler implements the exact same login as the default org.springframework.security.web.authentication
 * .SavedRequestAwareAuthenticationSuccessHandler with one notable difference – the redirect logic is removed
 *
 */
public final class RestAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();

    /**
     * Default Constructor.
     */
    public RestAuthenticationSuccessHandler() {

    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws ServletException, IOException {
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest == null) {
            clearAuthenticationAttributes(request);
            return;
        }
        String targetUrlParam = getTargetUrlParameter();
        if (isAlwaysUseDefaultTargetUrl()
                || (targetUrlParam != null && StringUtils.hasText(request.getParameter(targetUrlParam)))) {
            requestCache.removeRequest(request, response);
            clearAuthenticationAttributes(request);
            return;
        }
        clearAuthenticationAttributes(request);
    }

    /**
    *
    * @param cache - Request cache
    */
    public void setRequestCache(RequestCache cache) {
        this.requestCache = cache;
    }
}
