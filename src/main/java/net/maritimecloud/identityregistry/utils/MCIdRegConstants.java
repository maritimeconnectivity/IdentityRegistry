/*
 * Copyright 2017 Danish Maritime Authority.
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

public class MCIdRegConstants {
    public static final String MISSING_RIGHTS = "You do not have the needed rights.";
    public static final String ORG_NOT_FOUND = "The organization could not be found.";
    public static final String VESSEL_NOT_FOUND = "The vessel could not be found.";
    public static final String USER_NOT_FOUND = "The user could not be found.";
    public static final String DEVICE_NOT_FOUND = "The device could not be found.";
    public static final String ENTITY_NOT_FOUND = "The entity could not be found.";
    public static final String ROLE_NOT_FOUND = "The role could not be found.";
    public static final String URL_DATA_MISMATCH = "There is a mismatch between the url arguments and the data provided!";
    public static final String INVALID_REVOCATION_REASON = "The revocation reason is invalid!";
    public static final String INVALID_REVOCATION_DATE = "The revocation date must be set!";
    public static final String ORG_ALREADY_APPROVED = "This organization has already been approved!";
    public static final String COULD_NOT_GET_DATA_FROM_IDP = "Could not read data from Identity Provider!";
    public static final String INVALID_IDP_URL = "The Identity Provider URL is invalid!";
    public static final String ERROR_CREATING_KC_CLIENT = "An error occured while trying to register the service in the Identity Broker!";
    public static final String ERROR_CREATING_KC_USER = "An error occured while trying to create user of the Organization on shared Identity Provider!";
    public static final String ERROR_UPDATING_KC_USER = "An error occured while trying to update user of the Organization on shared Identity Provider!";
    public static final String ENTITY_ORG_ID_MISSING = "The organizational id of the entity is missing!";
    public static final String WRONG_ENTITY_ORG_ID_FORMAT = "The organizational id of the entity must be in lowercase and prefixed with the lowercase organization shortname follow by a dot!";
    public static final String INVALID_IMAGE = "Could not read the image format!";
    public static final String LOGO_NOT_FOUND = "This organization does not have a logo!";
    public static final String OIDC_MISSING_REDIRECT_URL = "This OpenID Connect Access Type requires a redirect URI!";
    public static final String BUG_REPORT_CREATION_FAILED = "Creation of bug report failed!";
    public static final String OIDC_CONF_FILE_NOT_AVAILABLE = "There is no OIDC configuration file available for this service!";
}
