package ltistarter.controllers;

import ltistarter.lti.LtiOidcUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;

@Controller
@RequestMapping("/oauth2/oidc/lti/prelogin")
public class Lti3OidcLoginInitPreprocessingController {

    /**
     * Hack to ensure an <code>iss</code>-derived <code>registrationId</code> is embedded into LTI 1.3 OIDC login init
     * URLs. SpringSecurity will seemingly always need a <code>registrationId</code>, but that it must be present on
     * the URL is really dictated by the use of
     * {@link org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver}. This is
     * potentially problematic for Platform-side LTI configurations which have historically depended on static
     * launch URLs. Complicating things further, tho, that assumption might simply no longer hold water since, as
     * noted in our {@link ltistarter.lti.LTI3OidcClientRegistrationRepository}, OIDC login init parameters don't
     * seem like they'll necessarily be sufficient to identify the correct Tool instance if there could be multiple
     * per Platform issuer (<code>iss</code>).
     *
     * @param request
     * @param iss
     * @return
     */
    // TODO Currently we're also struggling to support login init via <code>POST</code>, so this might become another
    //  way to work around that problem, but not yet sure what the root cause is.
    @GetMapping
    public ModelAndView doGet(HttpServletRequest request, @RequestParam("iss") String iss) {
        // base64 encode registrationId b/c if it's an iss then it's a URI and encoding a URI as a path components is
        // proving to be fraught, yes even when using Spring's UriUtils
        return new ModelAndView(String.format(
                "redirect:/oauth2/oidc/lti/login/%s?%s",
                LtiOidcUtils.encodeRegistrationId(iss),
                request.getQueryString()
        ));
    }

}
