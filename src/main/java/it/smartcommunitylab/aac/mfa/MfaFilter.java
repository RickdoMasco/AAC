package it.smartcommunitylab.aac.mfa;

import it.smartcommunitylab.aac.core.entrypoint.RealmAwarePathUriBuilder;
import java.io.IOException;
import java.time.Instant;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import it.smartcommunitylab.aac.core.auth.DefaultUserAuthenticationToken;
import it.smartcommunitylab.aac.core.auth.RealmAwareAuthenticationEntryPoint;
import it.smartcommunitylab.aac.model.Realm;
import it.smartcommunitylab.aac.model.Subject;
import it.smartcommunitylab.aac.realms.RealmManager;

public class MfaFilter extends OncePerRequestFilter {

    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final RealmAwareAuthenticationEntryPoint secondFactorAuthenticationEntryPoint;

    private final RealmManager realmManager;

    // Session Attribute for the MFA
    static private final String MFA_FIRST_TOKEN = "MFA_FIRST_TOKEN";
    static private final String MFA_TIMESTAMP = "MFA_TIMESTAMP";
    static private final String MFA_TRYNUMBER = "MFA_TRY_NUMBER";

    static int MAX_MFA_ATTEMPTS = 3;

    public MfaFilter(RealmManager realmManager, RealmAwarePathUriBuilder realmUriBuilder) {
        this.realmManager = realmManager;
        this.authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint("/login");
        this.secondFactorAuthenticationEntryPoint = new RealmAwareAuthenticationEntryPoint("/login");
        this.secondFactorAuthenticationEntryPoint.setUseForward(false);
        this.secondFactorAuthenticationEntryPoint.setRealmUriBuilder(realmUriBuilder);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(true);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (session.getAttribute(MFA_TRYNUMBER) != null && ((Number) session.getAttribute(MFA_TRYNUMBER)).intValue() >= MAX_MFA_ATTEMPTS) {
            handleMfaFailure(session, request, response, "mfa_max_attempts");
            return;
        }

        // Skip MFA if the realm does not require it
        if (isMfaSkipped(auth)) {
            filterChain.doFilter(request, response);
            return;
        }

        // MFA already completed, proceed
        if ((auth instanceof DefaultUserAuthenticationToken)
                && ((DefaultUserAuthenticationToken) auth).getAuthentications().size() >= 2) {
            filterChain.doFilter(request, response);
            return;
        }

        Object attr = session.getAttribute(MFA_FIRST_TOKEN);

        // Initiate MFA flow if no valid token exists
        if (!(attr instanceof Authentication)) {
            initiateMfaFlow(request, response, session, auth);
            return;
        }

        // No authenticated user found, proceed
        if (auth == null || !auth.isAuthenticated()) {
            // If MFA in progress, redirect back to second factor
            if (attr instanceof DefaultUserAuthenticationToken) {
                redirectToSecondFactor(request, response, (Authentication) attr, null);
                return;
            }
            filterChain.doFilter(request, response);
            return;
        }

        Authentication firstToken = (Authentication) attr;

        // Validate current token
        if (!isMfaValid(request, response, session, firstToken, auth)) {
            return;
        }

        // Both tokens are valid and belong to the same subject, finalize the MFA flow
        finalizeMfaFlow(session, (DefaultUserAuthenticationToken) firstToken, (DefaultUserAuthenticationToken) auth);
        filterChain.doFilter(request, response);
    }

    private boolean isMfaSkipped(Authentication auth) {
        if (!(auth instanceof DefaultUserAuthenticationToken))
            return true;

        DefaultUserAuthenticationToken token = (DefaultUserAuthenticationToken) auth;
        Realm realm = realmManager.findRealm(token.getRealm());
        return (realm != null && !realm.isMfaRequired());
    }

    private void initiateMfaFlow(HttpServletRequest request, HttpServletResponse response, HttpSession session,
            Authentication auth)
            throws IOException, ServletException {

        session.setAttribute(MFA_FIRST_TOKEN, auth);
        session.setAttribute(MFA_TIMESTAMP, Instant.now().getEpochSecond());
        session.setAttribute(MFA_TRYNUMBER, 0);

        SecurityContextHolder.clearContext();
        request.changeSessionId();

        redirectToSecondFactor(request, response, auth, null);
    }

    private boolean isMfaValid(HttpServletRequest request, HttpServletResponse response, HttpSession session,
            Authentication first, Authentication current) throws IOException, ServletException {

        long timestamp = ((Number) session.getAttribute(MFA_TIMESTAMP)).longValue();
        int tryNum = ((Number) session.getAttribute(MFA_TRYNUMBER)).intValue();


        if (timestamp + 60 < Instant.now().getEpochSecond()) {
            handleMfaFailure(session, request, response, "mfa_timeout");
            return false;
        }

        if (!(first instanceof DefaultUserAuthenticationToken)
                || !(current instanceof DefaultUserAuthenticationToken)) {
            session.setAttribute(MFA_TRYNUMBER, Integer.valueOf(tryNum + 1));
            session.setAttribute(MFA_TIMESTAMP, Long.valueOf(Instant.now().getEpochSecond()));
            handleMfaFailure(session, request, response, "mfa_invalid_token_type");
            return false;
        }

        String firstId = ((DefaultUserAuthenticationToken) first).getSubjectId();
        String currentId = ((DefaultUserAuthenticationToken) current).getSubjectId();

        if (!firstId.equals(currentId)) {
            session.setAttribute(MFA_TRYNUMBER, Integer.valueOf(tryNum + 1));
            session.setAttribute(MFA_TIMESTAMP, Long.valueOf(Instant.now().getEpochSecond()));
            handleMfaFailure(session, request, response, "mfa_subject_mismatch");
            return false;
        }

        if (current.equals(first)) {
            session.setAttribute(MFA_TRYNUMBER, Integer.valueOf(tryNum + 1));
            session.setAttribute(MFA_TIMESTAMP, Long.valueOf(Instant.now().getEpochSecond()));
            handleMfaFailure(session, request, response, "mfa_duplicate_token");
            return false;
        }

        return true;
    }

    private void handleMfaFailure(HttpSession session, HttpServletRequest request, HttpServletResponse response,
            String code)
            throws IOException, ServletException {

        // Clear auth on failure to avoid leaving in the context an authentication that
        // would force the filter to set the second factor token as the first factor
        // token on the next request, which would allow to login with the second factor
        // if u fail a first time the second factor. after the first fail if u use the
        // second factor linked to an another account again u can login to the account
        // linked to the second factor auth.
        SecurityContextHolder.clearContext();

        // Only clear MFA state if failure is terminal
        if (code.equals("mfa_timeout") || code.equals("mfa_max_attempts")) {
            session.removeAttribute(MFA_FIRST_TOKEN);
            session.removeAttribute(MFA_TIMESTAMP);
            session.removeAttribute(MFA_TRYNUMBER);
            authenticationEntryPoint.commence(request, response, new BadCredentialsException(code));
            return;
        }

        // Redirect back to 2nd factor page instead of /login to allow retries
        Authentication firstToken = (Authentication) session.getAttribute(MFA_FIRST_TOKEN);
        redirectToSecondFactor(request, response, firstToken, new BadCredentialsException(code));
    }

    private void finalizeMfaFlow(HttpSession session, DefaultUserAuthenticationToken ft,
            DefaultUserAuthenticationToken st) {

        DefaultUserAuthenticationToken combinedToken = new DefaultUserAuthenticationToken(
                (Subject) ft.getPrincipal(),
                ft.getRealm(),
                ft.getAuthorities(),
                ft,
                st);

        SecurityContextHolder.getContext().setAuthentication(combinedToken);

        session.removeAttribute(MFA_FIRST_TOKEN);
        session.removeAttribute(MFA_TRYNUMBER);
        session.removeAttribute(MFA_TIMESTAMP);
    }

    private void redirectToSecondFactor(HttpServletRequest request, HttpServletResponse response, Authentication auth,
            AuthenticationException ex)
            throws IOException, ServletException {

        String realm = ((DefaultUserAuthenticationToken) auth).getRealm();
        request.setAttribute("realm", realm);
        secondFactorAuthenticationEntryPoint.commence(request, response, ex);
    }
}