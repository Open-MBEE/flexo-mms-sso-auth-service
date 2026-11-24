package org.openmbee.flexo.mms.sso.oauth;

import org.springframework.http.HttpStatus;

/** OAuth protocol error (RFC 6749 section 5.2 error codes). */
public class OAuthException extends RuntimeException {

    private final String error;
    private final HttpStatus status;

    public OAuthException(HttpStatus status, String error, String description) {
        super(description);
        this.status = status;
        this.error = error;
    }

    public static OAuthException invalidRequest(String description) {
        return new OAuthException(HttpStatus.BAD_REQUEST, "invalid_request", description);
    }

    public static OAuthException invalidGrant(String description) {
        return new OAuthException(HttpStatus.BAD_REQUEST, "invalid_grant", description);
    }

    public static OAuthException invalidClient(String description) {
        return new OAuthException(HttpStatus.UNAUTHORIZED, "invalid_client", description);
    }

    public String getError() {
        return error;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
