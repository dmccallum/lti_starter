package ltistarter.lti;

import com.google.common.collect.ImmutableMap;
import ltistarter.model.Lti3KeyEntity;
import ltistarter.model.dto.LoginInitiationDTO;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.util.UUID;

@Component
public class LTI3OidcAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final LTI3OidcClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizationRequestResolver defaultResolver;
    private final LTIDataService ltiDataService;

    public LTI3OidcAuthorizationRequestResolver(LTI3OidcClientRegistrationRepository clientRegistrationRepository,
                                                LTIDataService ltiDataService) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.ltiDataService = ltiDataService;
        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository,
                "/oauth2/oidc/lti/login");
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest defaultRequest = defaultResolver.resolve(request);
        return prepare(defaultRequest, request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest defaultRequest = defaultResolver.resolve(request, clientRegistrationId);
        return prepare(defaultRequest, request);
    }

    private OAuth2AuthorizationRequest prepare(OAuth2AuthorizationRequest defaultRequest,
                                               HttpServletRequest origRequest) {
        if (defaultRequest == null) {
            return null;
        }
        LoginInitiationDTO loginInitiationDTO = new LoginInitiationDTO(origRequest);
        OAuth2AuthorizationRequest decoratedRequest =
                OAuth2AuthorizationRequest
                        .from(defaultRequest)
                        .additionalParameters(ImmutableMap.<String, Object>builder()
                                .putAll(defaultRequest.getAdditionalParameters())
                                .put("login_hint", loginInitiationDTO.getLoginHint())
                                .put("lti_message_hint", loginInitiationDTO.getLtiMessageHint())
                                .put("response_mode", "form_post")
                                .put("nonce", generateNonce())
                                .put("prompt", "none")
                                .build())
                        .build();
        // `state` depends on the augmented `additionalParameters`, so build another one...
        decoratedRequest =
                OAuth2AuthorizationRequest
                        .from(decoratedRequest)
                        .state(generateState(decoratedRequest, loginInitiationDTO))
                        .build();

        // And now the real hacking b/c OAuth2AuthorizationRequest is a final class and it doesn't allow
        // id_token as a flow type...
        String overriddenRequestUri = UriComponentsBuilder.fromUriString(decoratedRequest.getAuthorizationRequestUri())
                .replaceQueryParam("response_type", "id_token")
                .build(true)
                .toUriString();

        return OAuth2AuthorizationRequest
                .from(decoratedRequest)
                .authorizationRequestUri(overriddenRequestUri)
                .build();
    }

    private String generateState(OAuth2AuthorizationRequest request, LoginInitiationDTO loginInitiationDTO) {
        String registrationId = (String)request.getAdditionalParameters().get(OAuth2ParameterNames.REGISTRATION_ID);
        String nonce = (String)request.getAdditionalParameters().get("nonce");
        try {
            // TODO would be nice if we didn't have to look up the lti3KeyEntity once again...
            Lti3KeyEntity lti3KeyEntity = clientRegistrationRepository.findLti3KeyEntityByRegistrationId(registrationId);
            return LtiOidcUtils.generateState(
                    ltiDataService,
                    lti3KeyEntity,
                    ImmutableMap.of("nonce", nonce ),
                    loginInitiationDTO);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e); // TODO more descriptive exceptions, and/or just stop throwing checked exceptions period
        }
    }

    // TODO needs to be moved if it is to be verified when auth comes back. (Currently just doing the same thing
    //  as OIDCController
    private String generateNonce() {
        return UUID.randomUUID().toString();
    }

}
