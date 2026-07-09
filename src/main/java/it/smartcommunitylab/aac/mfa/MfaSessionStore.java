package it.smartcommunitylab.aac.mfa;

import java.time.Instant;
import javax.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;

/**
 * Session store for MFA state to decouple HttpSession from business logic.
 * This allows MfaFilter to operate on a simplified state interface rather than
 * manipulating session attributes directly.
 */
public class MfaSessionStore {

    private static final String MFA_FIRST_TOKEN = "MFA_FIRST_TOKEN";
    private static final String MFA_TIMESTAMP = "MFA_TIMESTAMP";
    private static final String MFA_TRYNUMBER = "MFA_TRY_NUMBER";

    private final HttpSession session;

    public MfaSessionStore(HttpSession session) {
        this.session = session;
    }

    /**
     * Initializes the MFA state in the session.
     */
    public void init(Authentication auth) {
        session.setAttribute(MFA_FIRST_TOKEN, auth);
        session.setAttribute(MFA_TIMESTAMP, Instant.now().getEpochSecond());
        session.setAttribute(MFA_TRYNUMBER, 0);
    }

    /**
     * Retrieves the first authentication token.
     */
    public Authentication getFirstToken() {
        Object attr = session.getAttribute(MFA_FIRST_TOKEN);
        if (attr instanceof Authentication) {
            return (Authentication) attr;
        }
        return null;
    }

    /**
     * Retrieves the current number of MFA attempts.
     */
    public int getTryNumber() {
        Object attr = session.getAttribute(MFA_TRYNUMBER);
        if (attr instanceof Number) {
            return ((Number) attr).intValue();
        }
        return 0;
    }

    /**
     * Retrieves the timestamp of the first MFA attempt.
     */
    public long getTimestamp() {
        Object attr = session.getAttribute(MFA_TIMESTAMP);
        if (attr instanceof Number) {
            return ((Number) attr).longValue();
        }
        return 0L;
    }

    /**
     * Increments the attempt counter and refreshes the timestamp.
     */
    public void incrementAttempts() {
        session.setAttribute(MFA_TRYNUMBER, getTryNumber() + 1);
        session.setAttribute(MFA_TIMESTAMP, Instant.now().getEpochSecond());
    }

    /**
     * Clears all MFA related state from the session.
     */
    public void clear() {
        session.removeAttribute(MFA_FIRST_TOKEN);
        session.removeAttribute(MFA_TIMESTAMP);
        session.removeAttribute(MFA_TRYNUMBER);
    }
}