package org.openmbee.flexo.mms.sso.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/** Opaque token generation, hashing and PKCE (RFC 7636) verification. */
public final class TokenHashing {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final java.util.regex.Pattern PKCE_VERIFIER = java.util.regex.Pattern.compile("^[A-Za-z0-9\\-._~]{43,128}$");

    private TokenHashing() {
    }

    public static String randomToken(int bytes) {
        byte[] raw = new byte[bytes];
        RANDOM.nextBytes(raw);
        return B64URL.encodeToString(raw);
    }

    public static String sha256(String value) {
        return B64URL.encodeToString(digest(value));
    }

    public static boolean isValidCodeChallenge(String challenge) {
        // base64url SHA-256 digest is always 43 characters
        return challenge != null && challenge.matches("^[A-Za-z0-9\\-_]{43}$");
    }

    public static boolean verifyPkce(String verifier, String challenge) {
        if (verifier == null || challenge == null || !PKCE_VERIFIER.matcher(verifier).matches()) {
            return false;
        }
        byte[] expected = sha256(verifier).getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(expected, challenge.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] digest(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
