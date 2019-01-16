package ltistarter.lti;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import ltistarter.model.Lti3KeyEntity;
import ltistarter.model.RSAKeyEntity;
import ltistarter.model.RSAKeyId;
import ltistarter.model.dto.LoginInitiationDTO;
import ltistarter.oauth.OAuthUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Base64Utils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

public class LtiOidcUtils {

    static final Logger log = LoggerFactory.getLogger(LtiOidcUtils.class);

    /**
     * The state will be returned when the tool makes the final call to us, so it is useful to send information
     * to our own tool, to know about the request.
     * @param lti3KeyEntity
     * @param authRequestMap
     * @param loginInitiationDTO
     * @return
     */
    public static String generateState(LTIDataService ltiDataService, Lti3KeyEntity lti3KeyEntity, Map<String, String> authRequestMap, LoginInitiationDTO loginInitiationDTO) throws GeneralSecurityException, IOException {

        Date date = new Date();
        Optional<RSAKeyEntity> rsaKeyEntityOptional = ltiDataService.getRepos().rsaKeys.findById(new RSAKeyId("OWNKEY",true));
        if (rsaKeyEntityOptional.isPresent()) {
            Key issPrivateKey = OAuthUtils.loadPrivateKey(rsaKeyEntityOptional.get().getPrivateKeyKey());
            String state = Jwts.builder()
                    .setHeaderParam("kid", "OWNKEY")  // The key id used to sign this
                    .setIssuer("ltiStarter")  //This is our own identifier, to know that we are the issuer.
                    .setSubject(lti3KeyEntity.getIss()) // We store here the platform issuer to check that matches with the issuer received later
                    .setAudience("Think about what goes here")  //TODO think about a useful value here
                    .setExpiration(DateUtils.addSeconds(date, 3600)) //a java.util.Date
                    .setNotBefore(date) //a java.util.Date
                    .setIssuedAt(date) // for example, now
                    .setId(authRequestMap.get("nonce")) //just a nonce... we don't use it by the moment, but it could be good if we store information about the requests in DB.
                    .claim("original_iss", loginInitiationDTO.getIss())  //All this claims are the information received in the OIDC initiation and some other useful things.
                    .claim("loginHint", loginInitiationDTO.getLoginHint())
                    .claim("ltiMessageHint", loginInitiationDTO.getLtiMessageHint())
                    .claim("targetLinkUri", loginInitiationDTO.getTargetLinkUri())
                    .claim("controller", "/oidc/login_initiations")
                    .signWith(SignatureAlgorithm.RS256, issPrivateKey)  //We sign it
                    .compact();
            log.debug("State: \n {} \n", state);
            return state;
        } else {
            throw new GeneralSecurityException("Error retrieving the state. No key was found.");
        }
    }

    public static String decodeRegistrationId(String registrationId) {
        byte[] bytes = Base64Utils.decodeFromString(registrationId);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    public static String encodeRegistrationId(String registrationId) {
        byte[] bytes = registrationId.getBytes(StandardCharsets.UTF_8);
        return Base64Utils.encodeToUrlSafeString(bytes);
    }

}
