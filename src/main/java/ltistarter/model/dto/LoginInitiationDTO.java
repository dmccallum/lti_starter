package ltistarter.model.dto;

public class LoginInitiationDTO {

    private String iss;
    private String loginHint;
    private String targetLinkUri;
    private String ltiMessageHint;

    public LoginInitiationDTO() {
    }

    public LoginInitiationDTO(String iss, String loginHint, String targetLinkUri, String ltiMessageHint) {
        this.iss = iss;
        this.loginHint = loginHint;
        this.targetLinkUri = targetLinkUri;
        this.ltiMessageHint = ltiMessageHint;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getLoginHint() {
        return loginHint;
    }

    public void setLoginHint(String loginHint) {
        this.loginHint = loginHint;
    }

    public String getTargetLinkUri() {
        return targetLinkUri;
    }

    public void setTargetLinkUri(String targetLinkUri) {
        this.targetLinkUri = targetLinkUri;
    }

    public String getLtiMessageHint() {
        return ltiMessageHint;
    }

    public void setLtiMessageHint(String ltiMessageHint) {
        this.ltiMessageHint = ltiMessageHint;
    }
}
