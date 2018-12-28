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

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import ltistarter.config.ApplicationConfig;
import ltistarter.model.KeyRequestEntity;
import ltistarter.model.LtiContextEntity;
import ltistarter.model.LtiKeyEntity;
import ltistarter.model.LtiLinkEntity;
import ltistarter.model.LtiMembershipEntity;
import ltistarter.model.LtiResultEntity;
import ltistarter.model.LtiServiceEntity;
import ltistarter.model.LtiUserEntity;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Key;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

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
    boolean updated = false;
    int loadingUpdates = 0;

    // these are populated on construct

    String ltiMessageType;
    String ltiVersion;

    String ltiGivenName;
    String ltiFamilyName;
    String ltiMiddleName;
    String ltiPicture;
    String ltiEmail;
    String ltiName;

    List<String> ltiRoles;
    List<String> ltiRoleScopeMentor;
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

    String lti11LegacyUserId;

    String nonce;
    String locale;

    Map<String, Object> ltiLaunchPresentation;
    String ltiPresTarget;
    int ltiPresWidth;
    int ltiPresHeight;
    String ltiPresReturnUrl;
    Locale ltiPresLocale;

    Map<String, Object> ltiExtension;
    Map<String, Object> ltiCustom;

    String ltiTargetLinkUrl;


    /**
     * @return the current LTI3Request object if there is one available, null if there isn't one and this is not a valid LTI3 based request
     */
    public static synchronized LTI3Request getInstance(Key key) {
        LTI3Request ltiRequest = null;
        try {
            ltiRequest = getInstanceOrDie(key);
        } catch (Exception e) {
            // nothing to do here
        }
        return ltiRequest;
    }

    /**
     * @return the current LTI3Request object if there is one available
     * @throws IllegalStateException if the LTI3Request cannot be obtained
     */
    public static LTI3Request getInstanceOrDie(Key key) {
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
                    ltiRequest = new LTI3Request(req, ltiDataService, true, key);
                } else {
                    ltiRequest = new LTI3Request(req, key);
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
     * @throws IllegalStateException if this is not an LTI request
     */
    public LTI3Request(HttpServletRequest request, Key key) {
        assert request != null : "cannot make an LtiRequest without a request";
        this.httpServletRequest = request;
        // extract the typical LTI data from the request
        String jwt = httpServletRequest.getParameter("id_token");
        Jws<Claims> jws = Jwts.parser().setSigningKey(key).parseClaimsJws(jwt);
        if (!isLTI3Request(jws)) {
            throw new IllegalStateException("Request is not an LTI3 request");
        }
        processRequestParameters(request,jws);
    }

    /**
     * @param request an http servlet request
     * @param ltiDataService   the service used for accessing LTI data
     * @param update  if true then update (or insert) the DB records for this request (else skip DB updating)
     * @throws IllegalStateException if this is not an LTI request
     */
    public LTI3Request(HttpServletRequest request, LTIDataService ltiDataService, boolean update, Key key) {
        this(request,key);
        assert ltiDataService != null : "LTIDataService cannot be null";
        ltiDataService.loadLTIDataFromDB(this);
        if (update) {
            ltiDataService.updateLTIDataInDB(this);
        }
        this.ltiDataService = ltiDataService;
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
     * @return true if this is a complete LTI request (includes key, context, link, user) OR false otherwise
     */
    //This is what we will need to change....
    public boolean processRequestParameters(HttpServletRequest request, Jws<Claims> jws) {
        if (request != null && this.httpServletRequest != request) {
            this.httpServletRequest = request;
        }
        assert this.httpServletRequest != null;

        /*
{
  "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
  "given_name": "Charley",
  "family_name": "Langosh",
  "middle_name": "Claris",
  "picture": "http://example.org/Charley.jpg",
  "email": "Charley.Langosh@example.org",
  "name": "Charley Claris Langosh",
  "https://purl.imsglobal.org/spec/lti/claim/roles": [
    "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner",
    "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Student",
    "http://purl.imsglobal.org/vocab/lis/v2/membership#Mentor"
  ],
  "https://purl.imsglobal.org/spec/lti/claim/role_scope_mentor": [
    "a62c52c02ba262003f5e"
  ],
  "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
    "id": "563",
    "title": "This is a resource link",
    "description": "The same than in the title"
  },
  "https://purl.imsglobal.org/spec/lti/claim/context": {
    "id": "115",
    "label": "How to learn LTI, but this is the label",
    "title": "How to learn LTI",
    "type": [
      "CourseOffering"
    ]
  },
  "https://purl.imsglobal.org/spec/lti/claim/tool_platform": {
    "name": "Test",
    "contact_email": "",
    "description": "",
    "url": "",
    "product_family_code": "",
    "version": "1.0"
  },
  "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint": {
    "scope": [
      "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
      "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
      "https://purl.imsglobal.org/spec/lti-ags/scope/score"
    ],
    "lineitems": "https://lti-ri.imsglobal.org/platforms/89/contexts/115/line_items"
  },
  "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice": {
    "context_memberships_url": "https://lti-ri.imsglobal.org/platforms/89/contexts/115/memberships",
    "service_versions": [
      "2.0"
    ]
  },
  "https://purl.imsglobal.org/spec/lti-ces/claim/caliper-endpoint-service": {
    "scopes": [
      "https://purl.imsglobal.org/spec/lti-ces/v1p0/scope/send"
    ],
    "caliper_endpoint_url": "https://lti-ri.imsglobal.org/platforms/89/sensors",
    "caliper_federated_session_id": "urn:uuid:d02afaf25974c0653bbc"
  },
  "iss": "https://sakai.org",
  "aud": "Ddbo123456",
  "iat": 1546015591,
  "exp": 1546015891,
  "sub": "9b063762698c1b77c955",
  "https://purl.imsglobal.org/spec/lti/claim/lti11_legacy_user_id": "9b063762698c1b77c955",
  "nonce": "c2339a10a2449deec455",
  "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
  "locale": "en-US",
  "https://purl.imsglobal.org/spec/lti/claim/launch_presentation": {
    "document_target": "iframe",
    "height": 320,
    "width": 240,
    "return_url": "https://lti-ri.imsglobal.org/platforms/89/returns"
  },
  "https://www.example.com/extension": {
    "color": "violet"
  },
  "https://purl.imsglobal.org/spec/lti/claim/custom": {
    "acolor": "blue",
    "color_count": 2
  },
  "https://purl.imsglobal.org/spec/lti/claim/target_link_uri": "https://localhost:9090/lti3"
} */




        ltiMessageType = jws.getBody().getOrDefault(LTI_MESSAGE_TYPE, null).toString();
        ltiVersion = jws.getBody().getOrDefault(LTI_VERSION, null).toString();

        ltiGivenName = jws.getBody().getOrDefault(LTI_GIVEN_NAME, null).toString();
        ltiFamilyName = jws.getBody().getOrDefault(LTI_FAMILY_NAME, null).toString();
        ltiMiddleName = jws.getBody().getOrDefault(LTI_MIDDLE_NAME, null).toString();
        ltiPicture = jws.getBody().getOrDefault(LTI_PICTURE, null).toString();
        ltiEmail = jws.getBody().getOrDefault(LTI_EMAIL, null).toString();
        ltiName = jws.getBody().getOrDefault(LTI_NAME, null).toString();

        ltiRoles = (List)jws.getBody().getOrDefault(LTI_ROLES, null);
        ltiRoleScopeMentor = (List)jws.getBody().getOrDefault(LTI_ROLE_SCOPE_MENTOR, null);

        ltiResourceLink = (Map)jws.getBody().getOrDefault(LTI_LINK, null);
        if (ltiResourceLink != null) {
            ltiLinkId = ltiResourceLink.getOrDefault(LTI_LINK_ID, null).toString();
            ltiLinkDescription = ltiResourceLink.getOrDefault(LTI_LINK_DESC, null).toString();
            ltiLinkTitle = ltiResourceLink.getOrDefault(LTI_LINK_TITLE, null).toString();
        }
        ltiContext = (Map)jws.getBody().getOrDefault(LTI_CONTEXT, null);
        if (ltiContext != null) {
            ltiContextId = ltiContext.getOrDefault(LTI_CONTEXT_ID, null).toString();
            ltiContextLabel = ltiContext.getOrDefault(LTI_CONTEXT_LABEL, null).toString();
            ltiContextTitle = ltiContext.getOrDefault(LTI_CONTEXT_TITLE, null).toString();
            ltiContextType = (List) ltiContext.getOrDefault(LTI_CONTEXT_TYPE, null);
        }

        ltiToolPlatform = (Map)jws.getBody().getOrDefault(LTI_PLATFORM, null);
        if (ltiToolPlatform != null) {
            ltiToolPlatformName = ltiToolPlatform.getOrDefault(LTI_PLATFORM_NAME, null).toString();
            ltiToolPlatformContactEmail = ltiToolPlatform.getOrDefault(LTI_PLATFORM_CONTACT_EMAIL, null).toString();
            ltiToolPlatformDesc = ltiToolPlatform.getOrDefault(LTI_PLATFORM_DESC, null).toString();
            ltiToolPlatformUrl = ltiToolPlatform.getOrDefault(LTI_PLATFORM_URL, null).toString();
            ltiToolPlatformProduct = ltiToolPlatform.getOrDefault(LTI_PLATFORM_PRODUCT, null).toString();
            ltiToolPlatformFamilyCode = ltiToolPlatform.getOrDefault(LTI_PLATFORM_PRODUCT_FAMILY_CODE, null).toString();
            ltiToolPlatformVersion = ltiToolPlatform.getOrDefault(LTI_PLATFORM_VERSION, null).toString();
        }

        ltiEndpoint = (Map)jws.getBody().getOrDefault(LTI_ENDPOINT, null);
        if (ltiEndpoint != null) {
            ltiEndpointScope = (List) ltiEndpoint.getOrDefault(LTI_ENDPOINT_SCOPE, null);
            ltiEndpointLineItems = ltiEndpoint.getOrDefault(LTI_ENDPOINT_LINEITEMS, null).toString();
        }

        ltiNamesRoleService = (Map)jws.getBody().getOrDefault(LTI_NAMES_ROLE_SERVICE, null);
        if (ltiNamesRoleService != null) {
            ltiNamesRoleServiceContextMembershipsUrl = ltiNamesRoleService.getOrDefault(LTI_NAMES_ROLE_SERVICE_CONTEXT, null).toString();
            ltiNamesRoleServiceVersions = (List) ltiNamesRoleService.getOrDefault(LTI_NAMES_ROLE_SERVICE_VERSIONS, null);
        }

        ltiCaliperEndpointService = (Map)jws.getBody().getOrDefault(LTI_CALIPER_ENDPOINT_SERVICE, null);
        if (ltiCaliperEndpointService != null) {
            ltiCaliperEndpointServiceScopes = (List) ltiCaliperEndpointService.getOrDefault(LTI_CALIPER_ENDPOINT_SERVICE_SCOPES, null);
            ltiCaliperEndpointServiceUrl = ltiCaliperEndpointService.getOrDefault(LTI_CALIPER_ENDPOINT_SERVICE_URL, null).toString();
            ltiCaliperEndpointServiceSessionId = ltiCaliperEndpointService.getOrDefault(LTI_CALIPER_ENDPOINT_SERVICE_SESSION_ID, null).toString();
        }

        iss = jws.getBody().getIssuer();
        aud = jws.getBody().getAudience();
        iat = jws.getBody().getIssuedAt();
        exp = jws.getBody().getExpiration();
        sub = jws.getBody().getSubject();
        nonce = jws.getBody().getOrDefault(LTI_NONCE, null).toString();

        lti11LegacyUserId = jws.getBody().getOrDefault(LTI_11_LEGACY_USER_ID, null).toString();

        String locale = jws.getBody().getOrDefault(LTI_PRES_LOCALE, null).toString();
        if (locale == null) {
            ltiPresLocale = Locale.getDefault();
        } else {
            ltiPresLocale = Locale.forLanguageTag(locale);
        }

        ltiLaunchPresentation = (Map)jws.getBody().getOrDefault(LTI_LAUNCH_PRESENTATION, null);
        if (ltiLaunchPresentation != null) {
            ltiPresHeight = Integer.valueOf(ltiLaunchPresentation.getOrDefault(LTI_PRES_HEIGHT, null).toString());
            ltiPresWidth = Integer.valueOf(ltiLaunchPresentation.getOrDefault(LTI_PRES_WIDTH, null).toString());
            ltiPresReturnUrl = ltiLaunchPresentation.getOrDefault(LTI_PRES_RETURN_URL, null).toString();
            ltiPresTarget = ltiLaunchPresentation.getOrDefault(LTI_PRES_TARGET, null).toString();
        }
        ltiCustom = (Map)jws.getBody().getOrDefault(LTI_CUSTOM, null);
        ltiExtension = (Map)jws.getBody().getOrDefault(LTI_EXTENSION, null);

        ltiTargetLinkUrl = jws.getBody().getOrDefault(LTI_TARGET_LINK_URI, null).toString();


        complete = checkCompleteLTIRequest(false);

        // A sample that shows how we can store some of this in the session
        HttpSession session = this.httpServletRequest.getSession();
        //session.setAttribute(LTI_USER_ID, ltiUserId);
        session.setAttribute(LTI_CONTEXT_ID, ltiContextId);

        return complete;
    }

    /**
     * Checks if this LTI3 request object has a complete set of required LTI data,
     * also sets the #complete variable appropriately
     *
     * @param objects if true then check for complete objects, else just check for complete request params
     * @return true if complete
     */
    //TODO update this to check the really complete conditions...!

    protected boolean checkCompleteLTIRequest(boolean objects) {
        if (objects && context != null && link != null ) {
            complete = true;
        } else if (!objects && ltiContextId != null && ltiLinkId != null ) {
            complete = true;
        } else {
            complete = false;
        }
        return complete;
    }

    // STATICS

    /**
     * @param jws the JWT token parsed.
     * @return true if this is a valid LTI request
     */
    public static boolean isLTI3Request(Jws<Claims> jws) {

        boolean valid = false;
        String ltiVersion = jws.getBody().get(LTI_VERSION,String.class);
        String ltiMessageType = jws.getBody().get(LTI_MESSAGE_TYPE,String.class);
        if (ltiMessageType != null && ltiVersion != null) {
            boolean goodMessageType = LTI_MESSAGE_TYPE_RESOURCE_LINK.equals(ltiMessageType);
            boolean goodLTIVersion = LTI_VERSION_3.equals(ltiVersion);
            valid = goodMessageType && goodLTIVersion;
        }
        // resource_link_id is also required
        return valid;
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
