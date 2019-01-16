package ltistarter.lti;

import ltistarter.model.Lti3KeyEntity;
import ltistarter.repository.Lti3KeyRepository;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;
import org.springframework.util.CollectionUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Component
public class LTI3OidcClientRegistrationRepository implements ClientRegistrationRepository {

    private final Lti3KeyRepository lti3KeyRepository;

    public LTI3OidcClientRegistrationRepository(Lti3KeyRepository lti3KeyRepository) {
        Assert.notNull(lti3KeyRepository, "Must specify a Lti3KeyRepository");
        this.lti3KeyRepository = lti3KeyRepository;
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        Lti3KeyEntity lti3KeyEntity = findLti3KeyEntityByRegistrationId(registrationId);
        return asClientRegistration(lti3KeyEntity);
    }

    public Lti3KeyEntity findLti3KeyEntityByRegistrationId(String registrationId) {
        // TODO probably can't just treat an iss can actually as a registrationId... registrationId probably
        //  needs to at least to be a combo of iss+clientId but for now we'll just assume iss so that the Platform
        //  doesn't need per-tool-configuration launch URLs (you wouldn't have those, for example, if you were
        //  deriving configurations from static metadata files as was done historically with LTI 1.1)... but whatever
        //  the registration ID is is, it has to be built from data we get in an OIDC init login request, which would be
        //  the URL, plus iss, login_hint, target_link_uri, and lti_message_hint fields. This impl assumes
        String decodeRegistrationId = LtiOidcUtils.decodeRegistrationId(registrationId);
        List<Lti3KeyEntity> matches = lti3KeyRepository.findByIss(decodeRegistrationId);
        if (CollectionUtils.isEmpty(matches)) {
            throw new IllegalArgumentException("No such issuer [" + registrationId + "]");
        }
        if (matches.size() > 1) {
            throw new IllegalArgumentException("Too many registrations for issuer [" + registrationId + "]");
        }
        return matches.get(0);
    }

    // TODO caching - probably don't need to construct this bad boy every time an iss requests a launch
    private ClientRegistration asClientRegistration(Lti3KeyEntity lti3KeyEntity) {
        return ClientRegistration
                .withRegistrationId(LtiOidcUtils.encodeRegistrationId(lti3KeyEntity.getIss()))
                .clientId(lti3KeyEntity.getClientId())

                // Not what we actually want, but strictly validates against a list of known values that don't
                // include OIDC's 'id_token' type. So we'll coerce it later.
                .authorizationGrantType(AuthorizationGrantType.IMPLICIT)

                .redirectUriTemplate("{baseUrl}/oauth2/oidc/lti/authorization")
                .scope("openid")
                .jwkSetUri(lti3KeyEntity.getJwksEndpoint())
                .authorizationUri(lti3KeyEntity.getOidcEndpoint())
                .build();
    }

}
