/**
 * Copyright 2014 Unicon (R)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ltistarter.lti;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.AsymmetricJWK;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import ltistarter.config.ApplicationConfig;
import ltistarter.model.Lti3KeyEntity;
import ltistarter.model.LtiContextEntity;
import ltistarter.model.LtiKeyEntity;
import ltistarter.model.LtiLinkEntity;
import ltistarter.model.LtiMembershipEntity;
import ltistarter.model.LtiResultEntity;
import ltistarter.model.LtiServiceEntity;
import ltistarter.model.LtiUserEntity;
import ltistarter.model.RSAKeyId;
import ltistarter.oauth.OAuthUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * LTI3 Request object holds all the details for a valid LTI3 request
 *
 * This is generally the only class that a developer will need to interact with but it will
 * only be available during incoming LTI3 requests (launches, etc.). Once the tool application
 * takes over and is servicing the requests on its own path this will no longer be available.
 *
 * Obtain this class using the static instance methods like so (recommended):
 * LTI3Request lti3Request = LTI3Request.getInstanceOrDie();
 *
 * Or by retrieving it from the HttpServletRequest attributes like so (best to not do this):
 * LTI3Request lti3Request = (LTI3Request) req.getAttribute(LTI3Request.class.getName());
 *
 * Devs may also need to use the LTIDataService service (injected) to access data when there is no
 * LTI request active.
 *
 * The main LTI data will also be placed into the Session and the Principal under the
 * LTI_USER_ID, LTI_CONTEXT_ID, and LTI_ROLE_ID constant keys.
 *
 */
public class LTI3Request {

    @Autowired
    LTIJWTService ltijwtService;

    final static Logger log = LoggerFactory.getLogger(LTI3Request.class);

    //BASICS
    public static final String LTI_MESSAGE_TYPE = "https://purl.imsglobal.org/spec/lti/claim/message_type";
    public static final String LTI_VERSION = "https://purl.imsglobal.org/spec/lti/claim/version";
    public static final String LTI_DEPLOYMENT_ID = "https://purl.imsglobal.org/spec/lti/claim/deployment_id";

    //RESOURCE_LINK
    public static final String LTI_LINK = "https://purl.imsglobal.org/spec/lti/claim/resource_link";
    public static final String LTI_LINK_ID = "id";
    public static final String LTI_LINK_DESC = "description";
    public static final String LTI_LINK_TITLE = "title";

    //ROLES
    public static final String LTI_ROLES = "https://purl.imsglobal.org/spec/lti/claim/roles";
    public static final String LTI_ROLE_SCOPE_MENTOR = "https://purl.imsglobal.org/spec/lti/claim/role_scope_mentor";
    //ROLES INSTITUTION
    public static final String LTI_ROLE_STUDENT = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Student";
    public static final String LTI_ROLE_LEARNER = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Learner";
    public static final String LTI_ROLE_MENTOR = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Mentor";
    public static final String LTI_ROLE_INSTRUCTOR = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Instructor ";
    public static final String LTI_ROLE_GUEST = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Guest";
    public static final String LTI_ROLE_OTHER = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Other";
    public static final String LTI_ROLE_STAFF = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Staff";
    public static final String LTI_ROLE_ALUMNI = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Alumni";
    public static final String LTI_ROLE_FACULTY = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Faculty";
    public static final String LTI_ROLE_MEMBER = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Member";
    public static final String LTI_ROLE_OBSERVER = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Observer";
    public static final String LTI_ROLE_PROSPECTIVE_STUDENT = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#ProspectiveStudent";
    public static final String LTI_ROLE_ADMIN = "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Administrator";
    //ROLES MEMBERSHIP
    //TODO Each of these has several subroles. Maybe it is better just to keep in the contant the "prefix" and find the role with the suffix(es)
    public static final String LTI_ROLE_MEMBERSHIP_ADMIN = "http://purl.imsglobal.org/vocab/lis/v2/membership#Administrator";
    public static final String LTI_ROLE_MEMBERSHIP_CONTENT_DEVELOPER = "http://purl.imsglobal.org/vocab/lis/v2/membership#ContentDeveloper";
    public static final String LTI_ROLE_MEMBERSHIP_INSTRUCTOR = "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor";
    public static final String LTI_ROLE_MEMBERSHIP_LEARNER = "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner";
    public static final String LTI_ROLE_MEMBERSHIP_MENTOR = "http://purl.imsglobal.org/vocab/lis/v2/membership#Mentor";
    public static final String LTI_ROLE_MEMBERSHIP_MANAGER = "http://purl.imsglobal.org/vocab/lis/v2/membership#Manager";
    public static final String LTI_ROLE_MEMBERSHIP_MEMBER = "http://purl.imsglobal.org/vocab/lis/v2/membership#Member";
    public static final String LTI_ROLE_MEMBERSHIP_OFFICER = "http://purl.imsglobal.org/vocab/lis/v2/membership#Officer";
    //ROLES SYSTEM
    public static final String LTI_ROLE_SYS_ADMININSTRATOR = "http://purl.imsglobal.org/vocab/lis/v2/system/person#Administrator";
    public static final String LTI_ROLE_NONE = "http://purl.imsglobal.org/vocab/lis/v2/system/person#None";
    public static final String LTI_ROLE_GENERAL = "http://purl.imsglobal.org/vocab/lis/v2/system/person#User";
    public static final String LTI_ROLE_ACCOUNT_ADMIN = "http://purl.imsglobal.org/vocab/lis/v2/system/person#AccountAdmin";
    public static final String LTI_ROLE_CREATOR = "http://purl.imsglobal.org/vocab/lis/v2/system/person#Creator";
    public static final String LTI_ROLE_SYS_ADMIN = "http://purl.imsglobal.org/vocab/lis/v2/system/person#SysAdmin";
    public static final String LTI_ROLE_SYS_SUPPORT = "http://purl.imsglobal.org/vocab/lis/v2/system/person#SysSupport";

    //CONTEXT
    public static final String LTI_CONTEXT = "https://purl.imsglobal.org/spec/lti/claim/context";
    public static final String LTI_CONTEXT_ID = "id";
    public static final String LTI_CONTEXT_TYPE = "type";
    public static final String LTI_CONTEXT_LABEL = "label";
    public static final String LTI_CONTEXT_TITLE = "title";
    public static final String LTI_CONTEXT_TYPE_COURSE_TEMPLATE = "http://purl.imsglobal.org/vocab/lis/v2/course#CourseTemplate";
    public static final String LTI_CONTEXT_TYPE_COURSE_OFFERING = "http://purl.imsglobal.org/vocab/lis/v2/course#CourseOffering";
    public static final String LTI_CONTEXT_TYPE_COURSE_SECTION = "http://purl.imsglobal.org/vocab/lis/v2/course#CourseSection";
    public static final String LTI_CONTEXT_TYPE_GROUP = "http://purl.imsglobal.org/vocab/lis/v2/course#Group";

    //PLATFORM
    public static final String LTI_PLATFORM = "https://purl.imsglobal.org/spec/lti/claim/tool_platform";
    public static final String LTI_PLATFORM_GUID = "guid";
    public static final String LTI_PLATFORM_CONTACT_EMAIL = "contact_email";
    public static final String LTI_PLATFORM_DESC = "description";
    public static final String LTI_PLATFORM_NAME = "name";
    public static final String LTI_PLATFORM_URL = "url";
    public static final String LTI_PLATFORM_PRODUCT = "product_family_code";
    public static final String LTI_PLATFORM_PRODUCT_FAMILY_CODE = "product_family_code";
    public static final String LTI_PLATFORM_VERSION = "version";

    //LAUNCH_PRESENTATION
    public static final String LTI_LAUNCH_PRESENTATION = "https://purl.imsglobal.org/spec/lti/claim/launch_presentation";
    public static final String LTI_PRES_TARGET = "document_target";
    public static final String LTI_PRES_WIDTH = "width";
    public static final String LTI_PRES_HEIGHT = "height";
    public static final String LTI_PRES_RETURN_URL = "return_url";
    public static final String LTI_PRES_LOCALE = "locale";
    public static final String LTI_PRES_RETURN_URL_PARAMETER_ERROR_MSG = "_ltierrormsg";
    public static final String LTI_PRES_RETURN_URL_PARAMETER_MSG = "_ltimsg";
    public static final String LTI_PRES_RETURN_URL_PARAMETER_ERROR_LOG = "_ltierrorlog";
    public static final String LTI_PRES_RETURN_URL_PARAMETER_LOG = "_ltilog";

    //LIS
    public static final String LTI_LIS ="https://purl.imsglobal.org/spec/lti/claim/lis";
    public static final String LTI_PERSON_SOURCEDID = "person_sourcedid";
    public static final String LTI_COURSE_OFFERING_SOURCEDID = "course_offering_sourcedid";
    public static final String LTI_COURSE_SECTION_SOURCEDID = "course_section_sourcedid";

    //CUSTOM AND EXTENSION TEST
    public static final String LTI_EXTENSION = "https://www.example.com/extension";
    public static final String LTI_CUSTOM = "https://purl.imsglobal.org/spec/lti/claim/custom";

    //OTHERS
    public static final String LTI_NAME = "name";
    public static final String LTI_GIVEN_NAME = "given_name";
    public static final String LTI_FAMILY_NAME = "family_name";
    public static final String LTI_MIDDLE_NAME = "middle_name";
    public static final String LTI_PICTURE = "picture";
    public static final String LTI_EMAIL = "email";
    public static final String LTI_LOCALE = "locale";
    public static final String LTI_ENDPOINT = "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint";
    public static final String LTI_ENDPOINT_SCOPE = "scope";
    public static final String LTI_ENDPOINT_LINEITEMS = "lineitems";
    public static final String LTI_NAMES_ROLE_SERVICE = "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice";
    public static final String LTI_NAMES_ROLE_SERVICE_CONTEXT = "context_memberships_url";
    public static final String LTI_NAMES_ROLE_SERVICE_VERSIONS = "service_versions";

    public static final String LTI_CALIPER_ENDPOINT_SERVICE = "https://purl.imsglobal.org/spec/lti-ces/claim/caliper-endpoint-service";
    public static final String LTI_CALIPER_ENDPOINT_SERVICE_SCOPES = "scopes";
    public static final String LTI_CALIPER_ENDPOINT_SERVICE_URL = "caliper_endpoint_url";
    public static final String LTI_CALIPER_ENDPOINT_SERVICE_SESSION_ID = "caliper_federated_session_id";

    public static final String LTI_11_LEGACY_USER_ID = "https://purl.imsglobal.org/spec/lti/claim/lti11_legacy_user_id";
    public static final String LTI_NONCE = "nonce";

    public static final String LTI_CONSUMER_KEY = "oauth_consumer_key";

    public static final String LTI_MESSAGE_TYPE_RESOURCE_LINK = "LtiResourceLinkRequest";
    public static final String LTI_VERSION_3 = "1.3.0";
    public static final String LTI_TARGET_LINK_URI =  "https://purl.imsglobal.org/spec/lti/claim/target_link_uri";


    HttpServletRequest httpServletRequest;
    LTIDataService ltiDataService;

    // these are populated by the loadLTIDataFromDB operation
    LtiKeyEntity key;
    LtiContextEntity context;
    LtiLinkEntity link;
    LtiMembershipEntity membership;
    LtiUserEntity user;
    LtiServiceEntity service;
    LtiResultEntity result;
    //ProfileEntity profile;
    boolean loaded = false;
    boolean complete = false;
    boolean correct = false;
    boolean updated = false;
    int loadingUpdates = 0;

    // these are populated on construct

    String ltiMessageType;
    String ltiVersion;
    String ltiDeploymentId;

    String ltiGivenName;
    String ltiFamilyName;
    String ltiMiddleName;
    String ltiPicture;
    String ltiEmail;
    String ltiName;

    List<String> ltiRoles;
    List<String> ltiRoleScopeMentor;
    int userRoleNumber;
    Map<String, Object> ltiResourceLink;
    String ltiLinkId;
    String ltiLinkTitle;
    String ltiLinkDescription;

    Map<String, Object> ltiContext;
    String ltiContextId;
    String ltiContextTitle;
    String ltiContextLabel;
    List<String> ltiContextType;

    Map<String, Object> ltiToolPlatform;
    String ltiToolPlatformName;
    String ltiToolPlatformContactEmail;
    String ltiToolPlatformDesc;
    String ltiToolPlatformUrl;
    String ltiToolPlatformProduct;
    String ltiToolPlatformFamilyCode;
    String ltiToolPlatformVersion;

    Map<String, Object> ltiEndpoint;
    List<String> ltiEndpointScope;
    String ltiEndpointLineItems;

    Map<String, Object> ltiNamesRoleService;
    String ltiNamesRoleServiceContextMembershipsUrl;
    List<String> ltiNamesRoleServiceVersions;

    Map<String, Object> ltiCaliperEndpointService;
    List<String> ltiCaliperEndpointServiceScopes;
    String ltiCaliperEndpointServiceUrl;
    String ltiCaliperEndpointServiceSessionId;

    String iss;
    String aud;
    Date iat;
    Date exp;
    String sub;
    String kid;

    String lti11LegacyUserId;

    String nonce;
    String locale;

    Map<String, Object> ltiLaunchPresentation;
    String ltiPresTarget;
    Integer ltiPresWidth;
    Integer ltiPresHeight;
    String ltiPresReturnUrl;
    Locale ltiPresLocale;

    Map<String, Object> ltiExtension;
    Map<String, Object> ltiCustom;

    String ltiTargetLinkUrl;


    /**
     * @return the current LTI3Request object if there is one available, null if there isn't one and this is not a valid LTI3 based request
     */
    public static synchronized LTI3Request getInstance() {
        LTI3Request ltiRequest = null;
        try {
            ltiRequest = getInstanceOrDie();
        } catch (Exception e) {
            //Nothing to do here
        }
        return ltiRequest;
    }

    /**
     * @return the current LTI3Request object if there is one available
     * @throws IllegalStateException if the LTI3Request cannot be obtained
     */
    public static LTI3Request getInstanceOrDie() throws IllegalStateException {
        ServletRequestAttributes sra = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest req = sra.getRequest();
        if (req == null) {
            throw new IllegalStateException("No HttpServletRequest can be found, cannot get the LTIRequest unless we are currently in a request");
        }
        LTI3Request ltiRequest = (LTI3Request) req.getAttribute(LTI3Request.class.getName());
        if (ltiRequest == null) {
            log.debug("No LTIRequest found, attempting to create one for the current request");
            LTIDataService ltiDataService = null;
            try {
                ltiDataService = ApplicationConfig.getContext().getBean(LTIDataService.class);
            } catch (Exception e) {
                log.warn("Unable to get the LTIDataService, initializing the LTIRequest without it");
            }
            try {
                if (ltiDataService != null) {
                    ltiRequest = new LTI3Request(req, ltiDataService, true);
                } else { //THIS SHOULD NOT HAPPEN
                    throw new IllegalStateException("Error internal, no Dataservice available: " + req);
                }
            } catch (Exception e) {
                log.warn("Failure trying to create the LTIRequest: " + e);
            }
        }
        if (ltiRequest == null) {
            throw new IllegalStateException("Invalid LTI request, cannot create LTIRequest from request: " + req);
        }
        return ltiRequest;
    }

    /**
     * @param request an http servlet request
     * @param ltiDataService   the service used for accessing LTI data
     * @param update  if true then update (or insert) the DB records for this request (else skip DB updating)
     * @throws IllegalStateException if this is not an LTI request
     */
    public LTI3Request(HttpServletRequest request, LTIDataService ltiDataService, boolean update) throws IllegalStateException {
        assert request != null : "cannot make an LtiRequest without a request";
        assert ltiDataService != null : "LTIDataService cannot be null";
        this.ltiDataService = ltiDataService;
        this.httpServletRequest = request;
        // extract the typical LTI data from the request
        String jwt = httpServletRequest.getParameter("id_token");
        Jws<Claims> jws = Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {

            // This is done because each state is signed with a different key based on the issuer... so
            // we don't know the key and we need to check it pre-extracting the claims and finding the kid
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                try {
                    // We are dealing with RS256 encryption, so we have some Oauth utils to manage the keys and
                    // convert them to keys from the string stored in DB. There are for sure other ways to manage this.
                    Lti3KeyEntity lti3KeyEntity = ltiDataService.getRepos().lti3KeyRepository.findByPlatformKid(header.getKeyId()).get(0);

                    if (lti3KeyEntity.getJwksEndpoint() != null) {
                        try {
                            JWKSet publicKeys = JWKSet.load(new URL(lti3KeyEntity.getJwksEndpoint()));
                            //JWKSet publicKeys = JWKSet.load(new File("jwtk.json"));
                            JWK jwk = publicKeys.getKeyByKeyId(lti3KeyEntity.getPlatformKid());
                            PublicKey key = ((AsymmetricJWK) jwk).toPublicKey();
                            return key;
                        } catch (JOSEException ex) {
                            log.error("Error getting the iss public key", ex);
                            return null;
                        } catch (ParseException | IOException ex) {
                            log.error("Error getting the iss public key", ex);
                            return null;
                        }
                    } else {
                        return OAuthUtils.loadPublicKey(ltiDataService.getRepos().rsaKeys.findById(new RSAKeyId(lti3KeyEntity.getPlatformKid(), false)).get().getKeyKey());
                    }
                } catch (GeneralSecurityException ex){
                    log.error("Error generating the tool public key",ex);
                    return null;
                }
            }
        }).parseClaimsJws(jwt);
        String isLTI3Request = isLTI3Request(jws);
        if (!isLTI3Request.equals("true")) {
            throw new IllegalStateException("Request is not a valid LTI3 request: " + isLTI3Request);
        }
        String processRequestParameters = processRequestParameters(request,jws);
        if (!processRequestParameters.equals("true")){
            throw new IllegalStateException("Request is not a valid LTI3 request: " + processRequestParameters);
        };

        //TODO
        ltiDataService.loadLTIDataFromDB(this);
        if (update) {
            ltiDataService.updateLTIDataInDB(this);
        }
    }

    /**
     * @param paramName the request parameter name
     * @return the value of the parameter OR null if there is none
     */
    public String getParam(String paramName) {
        String value = null;
        if (this.httpServletRequest != null && paramName != null) {
            value = StringUtils.trimToNull(this.httpServletRequest.getParameter(paramName));
        }
        return value;
    }

    /**
     * Processes all the parameters in this request into populated internal variables in the LTI Request
     *
     * @param request an http servlet request
     * @return true if this is a complete and correct LTI request (includes key, context, link, user) OR false otherwise
     */
    //This is what we will need to change....
    public String processRequestParameters(HttpServletRequest request, Jws<Claims> jws) {

        if (request != null && this.httpServletRequest != request) {
            this.httpServletRequest = request;
        }
        assert this.httpServletRequest != null;

        //First we get all the possible values, and we set null in the ones empty.
        // Later we will review those values to check if the request is valid or not.

        ltiMessageType = getStringFromLTIRequest(jws,LTI_MESSAGE_TYPE);
        ltiVersion = getStringFromLTIRequest(jws,LTI_VERSION);
        ltiDeploymentId = getStringFromLTIRequest(jws,LTI_DEPLOYMENT_ID);

        ltiGivenName = getStringFromLTIRequest(jws,LTI_GIVEN_NAME);
        ltiFamilyName = getStringFromLTIRequest(jws,LTI_FAMILY_NAME);
        ltiMiddleName = getStringFromLTIRequest(jws,LTI_MIDDLE_NAME);
        ltiPicture = getStringFromLTIRequest(jws,LTI_PICTURE);

        ltiEmail = getStringFromLTIRequest(jws,LTI_EMAIL);
        ltiName = getStringFromLTIRequest(jws,LTI_NAME);

        ltiRoles = getListFromLTIRequest(jws,LTI_ROLES);
        userRoleNumber = makeUserRoleNum(ltiRoles);
        ltiRoleScopeMentor = getListFromLTIRequest(jws,LTI_ROLE_SCOPE_MENTOR);

        ltiResourceLink = getMapFromLTIRequest(jws,LTI_LINK);
        if (ltiResourceLink != null) {
            ltiLinkId = getStringFromLTIRequestMap(ltiResourceLink,LTI_LINK_ID);
            ltiLinkDescription = getStringFromLTIRequestMap(ltiResourceLink,LTI_LINK_DESC);
            ltiLinkTitle = getStringFromLTIRequestMap(ltiResourceLink,LTI_LINK_TITLE);
        }
        ltiContext = getMapFromLTIRequest(jws,LTI_CONTEXT);
        if (ltiContext != null) {
            ltiContextId = getStringFromLTIRequestMap(ltiContext,LTI_CONTEXT_ID);
            ltiContextLabel = getStringFromLTIRequestMap(ltiContext,LTI_CONTEXT_LABEL);
            ltiContextTitle = getStringFromLTIRequestMap(ltiContext,LTI_CONTEXT_TITLE);
            ltiContextType = getListFromLTIRequestMap(ltiContext,LTI_CONTEXT_TYPE);
        }

        ltiToolPlatform = getMapFromLTIRequest(jws,LTI_PLATFORM);
        if (ltiToolPlatform != null) {
            ltiToolPlatformName = getStringFromLTIRequestMap(ltiToolPlatform,LTI_PLATFORM_NAME);
            ltiToolPlatformContactEmail = getStringFromLTIRequestMap(ltiToolPlatform,LTI_PLATFORM_CONTACT_EMAIL);
            ltiToolPlatformDesc = getStringFromLTIRequestMap(ltiToolPlatform,LTI_PLATFORM_DESC);
            ltiToolPlatformUrl = getStringFromLTIRequestMap(ltiToolPlatform,LTI_PLATFORM_URL);
            ltiToolPlatformProduct = getStringFromLTIRequestMap(ltiToolPlatform,LTI_PLATFORM_PRODUCT);
            ltiToolPlatformFamilyCode = getStringFromLTIRequestMap(ltiToolPlatform,LTI_PLATFORM_PRODUCT_FAMILY_CODE);
            ltiToolPlatformVersion = getStringFromLTIRequestMap(ltiToolPlatform,LTI_PLATFORM_VERSION);
        }

        ltiEndpoint = getMapFromLTIRequest(jws,LTI_ENDPOINT);
        if (ltiEndpoint != null) {
            ltiEndpointScope = getListFromLTIRequestMap(ltiEndpoint,LTI_ENDPOINT_SCOPE);
            ltiEndpointLineItems = getStringFromLTIRequestMap(ltiEndpoint,LTI_ENDPOINT_LINEITEMS);
        }

        ltiNamesRoleService = getMapFromLTIRequest(jws,LTI_NAMES_ROLE_SERVICE);
        if (ltiNamesRoleService != null) {
            ltiNamesRoleServiceContextMembershipsUrl = getStringFromLTIRequestMap(ltiNamesRoleService,LTI_NAMES_ROLE_SERVICE_CONTEXT);
            ltiNamesRoleServiceVersions = getListFromLTIRequestMap(ltiNamesRoleService,LTI_NAMES_ROLE_SERVICE_VERSIONS);
        }

        ltiCaliperEndpointService = getMapFromLTIRequest(jws,LTI_CALIPER_ENDPOINT_SERVICE);
        if (ltiCaliperEndpointService != null) {
            ltiCaliperEndpointServiceScopes = getListFromLTIRequestMap(ltiCaliperEndpointService, LTI_CALIPER_ENDPOINT_SERVICE_SCOPES);
            ltiCaliperEndpointServiceUrl = getStringFromLTIRequestMap(ltiCaliperEndpointService,LTI_CALIPER_ENDPOINT_SERVICE_URL);
            ltiCaliperEndpointServiceSessionId = getStringFromLTIRequestMap(ltiCaliperEndpointService,LTI_CALIPER_ENDPOINT_SERVICE_SESSION_ID);
        }

        iss = jws.getBody().getIssuer();
        aud = jws.getBody().getAudience();
        iat = jws.getBody().getIssuedAt();
        exp = jws.getBody().getExpiration();
        sub = jws.getBody().getSubject();
        nonce = getStringFromLTIRequest(jws,LTI_NONCE);

        lti11LegacyUserId = getStringFromLTIRequest(jws,LTI_11_LEGACY_USER_ID);

        String locale = getStringFromLTIRequest(jws,LTI_PRES_LOCALE);
        if (locale == null) {
            ltiPresLocale = Locale.getDefault();
        } else {
            ltiPresLocale = Locale.forLanguageTag(locale);
        }

        ltiLaunchPresentation = getMapFromLTIRequest(jws,LTI_LAUNCH_PRESENTATION);
        if (ltiLaunchPresentation != null) {
            ltiPresHeight = getIntegerFromLTIRequestMap(ltiLaunchPresentation,LTI_PRES_HEIGHT);
            ltiPresWidth = getIntegerFromLTIRequestMap(ltiLaunchPresentation,LTI_PRES_WIDTH);
            ltiPresReturnUrl = getStringFromLTIRequestMap(ltiLaunchPresentation,LTI_PRES_RETURN_URL);
            ltiPresTarget = getStringFromLTIRequestMap(ltiLaunchPresentation,LTI_PRES_TARGET);
        }
        ltiCustom = getMapFromLTIRequest(jws,LTI_CUSTOM);
        ltiExtension = getMapFromLTIRequest(jws,LTI_EXTENSION);

        ltiTargetLinkUrl = getStringFromLTIRequest(jws,LTI_TARGET_LINK_URI);

        // A sample that shows how we can store some of this in the session
        HttpSession session = this.httpServletRequest.getSession();
        //session.setAttribute(LTI_USER_ID, ltiUserId);
        session.setAttribute(LTI_CONTEXT_ID, ltiContextId);

        String isComplete = checkCompleteLTIRequest();
        String isCorrect = checkCorrectLTIRequest();

        if (isComplete.equals("true") && isCorrect.equals("true")) {
            return "true";
        } else {
            if (isComplete.equals("true")) {
                isComplete = "";
            } else if (isCorrect.equals("true")) {
                isCorrect = "";
            }
            return isComplete + isCorrect;
        }
    }

    private String getStringFromLTIRequest(Jws<Claims> jws, String stringToGet) {
        if (jws.getBody().containsKey(stringToGet)) {
            return jws.getBody().get(stringToGet, String.class);
        } else {
            return null;
        }
    }

    private String getStringFromLTIRequestMap(Map map, String stringToGet) {
        if (map.containsKey(stringToGet)) {
            return map.get(stringToGet).toString();
        } else {
            return null;
        }
    }

    private Integer getIntegerFromLTIRequestMap(Map map, String integerToGet) {
        if (map.containsKey(integerToGet)) {
            try {
                return Integer.valueOf(map.get(integerToGet).toString());
            }catch (Exception ex) {
                log.error("No integer when expected in: " + integerToGet + ". Returning null");
                return null;
            }
        } else {
            return null;
        }
    }

    private List<String> getListFromLTIRequestMap(Map map, String listToGet) {
        if (map.containsKey(listToGet)) {
            try {
                return (List)map.get(listToGet);
            }catch (Exception ex) {
                log.error("No list when expected in: " + listToGet + ". Returning null");
                return null;
            }
        } else {
            return null;
        }
    }

    private Map<String,Object> getMapFromLTIRequest(Jws<Claims> jws, String mapToGet) {
        if (jws.getBody().containsKey(mapToGet)) {
            try {
                return jws.getBody().get(mapToGet, Map.class);
            }catch (Exception ex) {
                log.error("No map integer when expected in: " + mapToGet + ". Returning null");
                return null;
            }
        } else {
            return null;
        }
    }

    private List<String> getListFromLTIRequest(Jws<Claims> jws, String listToGet) {
        if (jws.getBody().containsKey(listToGet)) {
            try {
                return jws.getBody().get(listToGet, List.class);
            }catch (Exception ex) {
                log.error("No map integer when expected in: " + listToGet + ". Returning null");
                return null;
            }
        } else {
            return null;
        }
    }


    /**
     * Checks if this LTI request object has a complete set of required LTI data,
     * also sets the #complete variable appropriately
     *
     * @param objects if true then check for complete objects, else just check for complete request params
     * @return true if complete
     */
    protected boolean checkCompleteLTIRequest(boolean objects) {
        if (objects && key != null && context != null && link != null && user != null) {
            return true;
        } else {
            return false;
        }
    }


    /**
     * Checks if this LTI3 request object has a complete set of required LTI3 data,
     * NOTE: this code is not the one I would create for production, it is more a didactic one
     * to understand what is being checked.
     *
     * @return true if complete
     */

    protected String checkCompleteLTIRequest() {

        String complete = "";

        if (StringUtils.isEmpty(ltiDeploymentId)) {
            complete += " Lti Deployment Id is empty.\n ";
        }
        if (ltiResourceLink == null || ltiResourceLink.size() == 0) {
            complete += " Lti Resource Link is empty.\n ";
        } else {
            if (StringUtils.isEmpty(ltiLinkId)) {
                complete += " Lti Resource Link ID is empty.\n ";
            }
        }
        if (StringUtils.isEmpty(sub)) {
            complete += " User (sub) is empty.\n ";
        }
        if (ltiRoles == null || ltiRoles.size() == 0) {
            complete += " Lti Roles is empty.\n ";
        }
        if (exp == null ){
            complete += " Exp is empty or invalid.\n ";
        }
        if (iat == null ){
            complete += " Iat is empty or invalid.\n ";
        }

        if (complete.equals("")) {
            return "true";
        } else {
            return complete;
        }
    }

    /**
     * Checks if this LTI3 request object has correct values
     *
     * @return the string "true" if complete and the error message if not
     */
    //TODO update this to check the really complete conditions...!

    protected String checkCorrectLTIRequest() {

        String correct = "true";


        //TODO check things as:
        // Roles are correct roles
        //

        return correct;
    }

    // STATICS

    /**
     * @param jws the JWT token parsed.
     * @return true if this is a valid LTI request
     */
    public static String isLTI3Request(Jws<Claims> jws) {

        String errorDetail = "";
        boolean valid = false;
        String ltiVersion = jws.getBody().get(LTI_VERSION,String.class);
        if (ltiVersion == null) {errorDetail = "LTI Version = null. ";}
        String ltiMessageType = jws.getBody().get(LTI_MESSAGE_TYPE,String.class);
        if (ltiMessageType == null) {errorDetail += "LTI Message Type = null. ";}
            if (ltiMessageType != null && ltiVersion != null) {
            boolean goodMessageType = LTI_MESSAGE_TYPE_RESOURCE_LINK.equals(ltiMessageType);
            if (!goodMessageType) {errorDetail = "LTI Message Type is not right: " + ltiMessageType + ". ";}
            boolean goodLTIVersion = LTI_VERSION_3.equals(ltiVersion);
            if (!goodLTIVersion) {errorDetail += "LTI Version is not right: " + ltiVersion;}
            valid = goodMessageType && goodLTIVersion;
        }
        if (valid) {
            return "true";
        }else {
            return errorDetail;
        }
    }


    /**
     * @param rawUserRoles the raw roles string (this could also only be part of the string assuming it is the highest one)
     * @return the number that represents the role (higher is more access)
     */
    public static int makeUserRoleNum(List<String> rawUserRoles) {
        int roleNum = 0;
        if (rawUserRoles != null) {
            if (rawUserRoles.contains(LTI_ROLE_MEMBERSHIP_ADMIN)) {
                roleNum = 2;
            } else if (rawUserRoles.contains(LTI_ROLE_MEMBERSHIP_INSTRUCTOR)) {
                roleNum = 1;
            }
        }
        return roleNum;
    }


    /**
     * Use Jackson to convert some JSON to a map
     *
     * @param json input JSON
     * @return the map
     * @throws IllegalArgumentException if the json is invalid
     */
    public static Map<String, Object> jsonToMap(final String json) {
        if (StringUtils.isBlank(json)) {
            throw new IllegalArgumentException("Invalid json: blank/empty/null string");
        }
        Map<String, Object> map = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        try {
            //noinspection unchecked
            map = mapper.readValue(json, Map.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid json: " + e.getMessage(), e);
        }
        return map;
    }

    /**
     * Use Jackson to check if some JSON is valid
     *
     * @param json a chunk of json
     * @return true if valid
     */
    public static boolean isValidJSON(final String json) {
        boolean valid;
        if (StringUtils.isBlank(json)) {
            return false;
        }
        try {
            JsonParser parser = null;
            try {
                parser = new ObjectMapper().getFactory().createParser(json);
                //noinspection StatementWithEmptyBody
                while (parser.nextToken() != null) {
                }
                valid = true;
            } catch (JsonParseException jpe) {
                valid = false;
            } finally {
                if (parser != null) {
                    parser.close();
                }
            }
        } catch (IOException e) {
            valid = false;
        }
        return valid;
    }

    // GETTERS


    public LtiKeyEntity getKey() {
        return key;
    }

    public LtiContextEntity getContext() {
        return context;
    }

    public LtiLinkEntity getLink() {
        return link;
    }

    public LtiMembershipEntity getMembership() {
        return membership;
    }

    public LtiUserEntity getUser() {
        return user;
    }

    public LtiServiceEntity getService() {
        return service;
    }

    public LtiResultEntity getResult() {
        return result;
    }

    public boolean isLoaded() {
        return loaded;
    }

    public boolean isComplete() {
        return complete;
    }

    public boolean isUpdated() {
        return updated;
    }

    public int getLoadingUpdates() {
        return loadingUpdates;
    }

    public String getLtiMessageType() {
        return ltiMessageType;
    }

    public String getLtiVersion() {
        return ltiVersion;
    }

    public String getLtiGivenName() {
        return ltiGivenName;
    }

    public String getLtiFamilyName() {
        return ltiFamilyName;
    }

    public String getLtiMiddleName() {
        return ltiMiddleName;
    }

    public String getLtiPicture() {
        return ltiPicture;
    }

    public String getLtiEmail() {
        return ltiEmail;
    }

    public String getLtiName() {
        return ltiName;
    }

    public List<String> getLtiRoles() {
        return ltiRoles;
    }

    public List<String> getLtiRoleScopeMentor() {
        return ltiRoleScopeMentor;
    }

    public Map<String, Object> getLtiResourceLink() {
        return ltiResourceLink;
    }

    public String getLtiLinkId() {
        return ltiLinkId;
    }

    public String getLtiLinkTitle() {
        return ltiLinkTitle;
    }

    public String getLtiLinkDescription() {
        return ltiLinkDescription;
    }

    public Map<String, Object> getLtiContext() {
        return ltiContext;
    }

    public String getLtiContextId() {
        return ltiContextId;
    }

    public String getLtiContextTitle() {
        return ltiContextTitle;
    }

    public String getLtiContextLabel() {
        return ltiContextLabel;
    }

    public List<String> getLtiContextType() {
        return ltiContextType;
    }

    public Map<String, Object> getLtiToolPlatform() {
        return ltiToolPlatform;
    }

    public String getLtiToolPlatformName() {
        return ltiToolPlatformName;
    }

    public String getLtiToolPlatformContactEmail() {
        return ltiToolPlatformContactEmail;
    }

    public String getLtiToolPlatformDesc() {
        return ltiToolPlatformDesc;
    }

    public String getLtiToolPlatformUrl() {
        return ltiToolPlatformUrl;
    }

    public String getLtiToolPlatformProduct() {
        return ltiToolPlatformProduct;
    }

    public String getLtiToolPlatformFamilyCode() {
        return ltiToolPlatformFamilyCode;
    }

    public String getLtiToolPlatformVersion() {
        return ltiToolPlatformVersion;
    }

    public Map<String, Object> getLtiEndpoint() {
        return ltiEndpoint;
    }

    public List<String> getLtiEndpointScope() {
        return ltiEndpointScope;
    }

    public String getLtiEndpointLineItems() {
        return ltiEndpointLineItems;
    }

    public Map<String, Object> getLtiNamesRoleService() {
        return ltiNamesRoleService;
    }

    public String getLtiNamesRoleServiceContextMembershipsUrl() {
        return ltiNamesRoleServiceContextMembershipsUrl;
    }

    public List<String> getLtiNamesRoleServiceVersions() {
        return ltiNamesRoleServiceVersions;
    }

    public Map<String, Object> getLtiCaliperEndpointService() {
        return ltiCaliperEndpointService;
    }

    public List<String> getLtiCaliperEndpointServiceScopes() {
        return ltiCaliperEndpointServiceScopes;
    }

    public String getLtiCaliperEndpointServiceUrl() {
        return ltiCaliperEndpointServiceUrl;
    }

    public String getLtiCaliperEndpointServiceSessionId() {
        return ltiCaliperEndpointServiceSessionId;
    }

    public String getIss() {
        return iss;
    }

    public String getAud() {
        return aud;
    }

    public Date getIat() {
        return iat;
    }

    public Date getExp() {
        return exp;
    }

    public String getSub() {
        return sub;
    }

    public String getLti11LegacyUserId() {
        return lti11LegacyUserId;
    }

    public String getNonce() {
        return nonce;
    }

    public String getLocale() {
        return locale;
    }

    public Map<String, Object> getLtiLaunchPresentation() {
        return ltiLaunchPresentation;
    }

    public String getLtiPresTarget() {
        return ltiPresTarget;
    }

    public int getLtiPresWidth() {
        return ltiPresWidth;
    }

    public int getLtiPresHeight() {
        return ltiPresHeight;
    }

    public String getLtiPresReturnUrl() {
        return ltiPresReturnUrl;
    }

    public Locale getLtiPresLocale() {
        return ltiPresLocale;
    }

    public Map<String, Object> getLtiExtension() {
        return ltiExtension;
    }

    public Map<String, Object> getLtiCustom() {
        return ltiCustom;
    }

    public String getLtiTargetLinkUrl() {
        return ltiTargetLinkUrl;
    }
}
