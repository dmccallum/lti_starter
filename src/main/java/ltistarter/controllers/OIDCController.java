/**
 * Copyright 2019 Unicon (R)
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
package ltistarter.controllers;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import ltistarter.lti.LTIDataService;
import ltistarter.model.IssConfigurationEntity;
import ltistarter.model.RSAKeyId;
import ltistarter.model.dto.LoginInitiationDTO;
import ltistarter.oauth.OAuthUtils;
import ltistarter.repository.IssConfigurationRepository;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * This LTI controller should be protected by OAuth 1.0a (on the /oauth path)
 * This will handle LTI 1 and 2 (many of the paths ONLY make sense for LTI2 though)
 * Sample Key "key" and secret "secret"
 */
@Controller
@RequestMapping("/oidc")
public class OIDCController extends BaseController {

    //Constants defined in the LTI standard
    private final String NONE = "none";
    private final String FORM_POST = "form_post";
    private final String ID_TOKEN = "id_token";
    private final String OPENID = "openid";

    @Autowired
    IssConfigurationRepository issConfigurationRepository;

    @Autowired
    LTIDataService ltiDataService;

    /**
     * This will receive the request to start the OIDC process.
     * We receive some parameters in the url (iss, login_hint, target_link_uri, lti_message_hint)
     * @param req
     * @param model
     * @return
     */
    @RequestMapping("/login_initiations")
    public String loginInitiations(HttpServletRequest req, Model model) {

        LoginInitiationDTO loginInitiationDTO = new LoginInitiationDTO(req.getParameter("iss"),
                req.getParameter("login_hint"),
                req.getParameter("target_link_uri"),
                req.getParameter("lti_message_hint"));
        // Search for the configuration for that issuer
        List<IssConfigurationEntity> issConfigurationEntityList =issConfigurationRepository.findByIss(loginInitiationDTO.getIss());
        // We deal with some possible errors
        if (issConfigurationEntityList.isEmpty()) {  //If we don't have configuration
            model.addAttribute("error_type","iss_nonexisting");
            return "error";
        } else {
            // If we have more than one configuration for the same iss, at this moment we don't know about the client id, so we just pick the first one
            IssConfigurationEntity issConfigurationEntity = issConfigurationEntityList.get(0);
            Map<String, String> parameters = generateAuthRequestPayload(issConfigurationEntity,loginInitiationDTO);
            model.addAllAttributes(parameters);
            return "oicdRedirect";
        }
    }

    /**
     * This generates a map with all the information that we need to send to the OIDC Authorization endpoint in the Platform.
     * In this case, we will put this in the model to be used by the thymeleaf template.
     * @param issConfigurationEntity
     * @param loginInitiationDTO
     * @return
     */
    private Map<String, String> generateAuthRequestPayload (IssConfigurationEntity issConfigurationEntity, LoginInitiationDTO loginInitiationDTO) {

        Map<String, String> authRequestMap =  new HashMap<>();
        authRequestMap.put("client_id",issConfigurationEntity.getClientId()); //As it came from the Platform
        authRequestMap.put("login_hint",loginInitiationDTO.getLoginHint()); //As it came from the Platform
        authRequestMap.put("lti_message_hint",loginInitiationDTO.getLtiMessageHint()); //As it came from the Platform
        authRequestMap.put("nonce",UUID.randomUUID().toString());  //Just a nonce
        authRequestMap.put("prompt",NONE);  //Always this value
        //TODO be sure this is ok!!! I think I have a little mess with the redirect and target Link Url...
        // IMO, the target link will be resolved later... in the redirect controller... that checks that all is ok and then
        // redirect to the target link.
        authRequestMap.put("redirect_uri",loginInitiationDTO.getTargetLinkUri());  //As it came from the Platform
        authRequestMap.put("response_mode",FORM_POST); //Always this value
        authRequestMap.put("response_type",ID_TOKEN); //Always this value
        authRequestMap.put("scope",OPENID);  //Always this value
        String state = generateState(issConfigurationEntity,authRequestMap,loginInitiationDTO);
        authRequestMap.put("state",state); //The state we use later to retrieve some useful information about the OICD request.
        authRequestMap.put("oicdEndpoint",issConfigurationEntity.getOidcEndpoint());  //For the post
        authRequestMap.put("oicdEndpointComplete",generateCompleteUrl(authRequestMap));  //For the GET with all the query string parameters
        return authRequestMap;
    }

    /**
     * The state will be returned when the tool makes the final call to us, so it is useful to send information
     * to our own tool, to know about the request.
     * @param issConfigurationEntity
     * @param authRequestMap
     * @param loginInitiationDTO
     * @return
     */
    private String generateState(IssConfigurationEntity issConfigurationEntity, Map<String, String> authRequestMap, LoginInitiationDTO loginInitiationDTO) {

        try{
        Date date = new Date();
        Key issPrivateKey = OAuthUtils.loadPrivateKey(ltiDataService.getRepos().rsaKeys.findById(new RSAKeyId(issConfigurationEntity.getToolKid(),true)).get().getKeyKey());

        String state = Jwts.builder()
                .setHeaderParam("kid",issConfigurationEntity.getToolKid())  // The key id used to sign this
                .setIssuer("ltiStarter")  //This is our own identifier, to know that we are the issuer.
                .setSubject(issConfigurationEntity.getIss()) // We store here the platform issuer to check that matches with the issuer received later
                .setAudience("Think about what goes here")  //TODO think about a useful value here
                .setExpiration(DateUtils.addSeconds(date,3600)) //a java.util.Date
                .setNotBefore(date) //a java.util.Date
                .setIssuedAt(date) // for example, now
                .setId(authRequestMap.get("nounce")) //just a nounce... we don't use it by the moment, but it could be good if we store information about the requests in DB.
                .claim("original_iss", loginInitiationDTO.getIss())  //All this claims are the information received in the OIDC initiation and some other useful things.
                .claim("loginHint", loginInitiationDTO.getLoginHint())
                .claim("ltiMessageHint", loginInitiationDTO.getLtiMessageHint())
                .claim("targetLinkUri", loginInitiationDTO.getTargetLinkUri())
                .claim("controller", "/oidc/login_initiations" )  //TODO add more things if we need it later
                .signWith(SignatureAlgorithm.RS256, issPrivateKey)  //We sign it
                .compact();
                log.info("State: \n" + state + "\n");
        return state;
        } catch (GeneralSecurityException | IOException ex){
            log.error("Error generating the private key",ex);
            //TODO something better here.
            return null;
        }
    }

    /**
     * This generates the GET URL with all the query string parameters.
     * @param model
     * @return
     */
    private String generateCompleteUrl(Map<String, String> model) {
        String url = new StringBuilder()
                .append(model.get("oicdEndpoint"))
                .append("?client_id=")
                .append(model.get("client_id"))
                .append("&login_hint=")
                .append(model.get("login_hint"))
                .append("&lti_message_hint=")
                .append(model.get("lti_message_hint"))
                .append("&nonce=")
                .append(model.get("nonce"))
                .append("&prompt=")
                .append(model.get("prompt"))
                .append("&redirect_uri=")
                .append(model.get("redirect_uri"))
                .append("&response_mode=")
                .append(model.get("response_mode"))
                .append("&response_type=")
                .append(model.get("response_type"))
                .append("&scope=")
                .append(model.get("scope"))
                .append("&state=")
                .append(model.get("state")).toString();
        return url;
    }

}
