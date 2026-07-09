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

import it.smartcommunitylab.aac.Config;
import it.smartcommunitylab.aac.core.auth.DefaultUserAuthenticationToken;
import it.smartcommunitylab.aac.core.auth.RealmAwareAuthenticationEntryPoint;
import it.smartcommunitylab.aac.model.Realm;
import it.smartcommunitylab.aac.model.Subject;
import it.smartcommunitylab.aac.realms.RealmManager;

public class MfaFilter extends OncePerRequestFilter {

    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final RealmAwareAuthenticationEntryPoint secondFactorAuthenticationEntryPoint;
    private final RealmManager realmManager;

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
        MfaSessionStore store = new MfaSessionStore(session);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Check if maximum attempts were already reached
        if (store.getTryNumber() >= Config.MAX_MFA_ATTEMPTS) {
            handleMfaFailure(store, request, response, "mfa_max_attempts");
            return;
        }

        // Skip MFA if the realm does not require it or auth type is unknown
        if (isMfaSkipped(auth)) {
            filterChain.doFilter(request, response);
            return;
        }

        // MFA already completed, proceed
        if (auth instanceof DefaultUserAuthenticationToken
                && ((DefaultUserAuthenticationToken) auth).getAuthentications().size() >= 2) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication firstToken = store.getFirstToken();

        // Initiate MFA flow if no active first factor exists
        if (firstToken == null) {
            initiateMfaFlow(store, request, response, auth);
            return;
        }

        // In progress: redirect to second factor if context not yet authenticated
        if (auth == null || !auth.isAuthenticated()) {
            redirectToSecondFactor(request, response, firstToken, null);
            return;
        }

        // Validate current token against the first token
        long now = Instant.now().getEpochSecond();
        if (!isMfaValid(firstToken, auth, store.getTimestamp(), now)) {
            store.incrementAttempts();
            handleMfaFailure(store, request, response, "mfa_invalid_token");
            return;
        }

        // Both tokens are valid and belong to the same subject, finalize the MFA flow
        finalizeMfaFlow(store, (DefaultUserAuthenticationToken) firstToken, (DefaultUserAuthenticationToken) auth);
        filterChain.doFilter(request, response);
    }

    private boolean isMfaSkipped(Authentication auth) {
        if (auth == null || !(auth instanceof DefaultUserAuthenticationToken)) {
            return true;
        }

        DefaultUserAuthenticationToken token = (DefaultUserAuthenticationToken) auth;
        Realm realm = realmManager.findRealm(token.getRealm());
        if (realm != null) {
            return !realm.isMfaRequired();
        }
        return false;
    }

    private void initiateMfaFlow(MfaSessionStore store, HttpServletRequest request, HttpServletResponse response,
            Authentication auth)
            throws IOException, ServletException {

        store.init(auth);

        SecurityContextHolder.clearContext();
        request.changeSessionId();

        redirectToSecondFactor(request, response, auth, null);
    }

    /**
     * Pure validation logic. Does not touch the session.
     */
    private boolean isMfaValid(Authentication first, Authentication current, long timestamp, long now) {
        // Timeout check
        if (timestamp + 60 < now) {
            return false; 
        }

        if (!(first instanceof DefaultUserAuthenticationToken)
                || !(current instanceof DefaultUserAuthenticationToken)) {
            return false;
        }

        DefaultUserAuthenticationToken ft = (DefaultUserAuthenticationToken) first;
        DefaultUserAuthenticationToken ct = (DefaultUserAuthenticationToken) current;

        // Subject mismatch or duplicate token
        if (!ft.getSubjectId().equals(ct.getSubjectId()) || ct.equals(ft)) {
            return false;
        }

        return true;
    }

    private void handleMfaFailure(MfaSessionStore store, HttpServletRequest request, HttpServletResponse response,
            String code)
            throws IOException, ServletException {

        SecurityContextHolder.clearContext();

        // Only clear MFA state if failure is terminal
        if (code.equals("mfa_timeout") || code.equals("mfa_max_attempts")) {
            store.clear();
            authenticationEntryPoint.commence(request, response, new BadCredentialsException(code));
            return;
        }

        // Redirect back to 2nd factor page to allow retries
        Authentication firstToken = store.getFirstToken();
        redirectToSecondFactor(request, response, firstToken, new BadCredentialsException(code));
    }

    private void finalizeMfaFlow(MfaSessionStore store, DefaultUserAuthenticationToken ft,
            DefaultUserAuthenticationToken st) {

        DefaultUserAuthenticationToken combinedToken = new DefaultUserAuthenticationToken(
                (Subject) ft.getPrincipal(),
                ft.getRealm(),
                ft.getAuthorities(),
                ft,
                st);

        SecurityContextHolder.getContext().setAuthentication(combinedToken);
        store.clear();
    }

    private void redirectToSecondFactor(HttpServletRequest request, HttpServletResponse response, Authentication auth,
            AuthenticationException ex)
            throws IOException, ServletException {

        if (!(auth instanceof DefaultUserAuthenticationToken)) {
            AuthenticationException exception = ex;
            if (exception == null) {
                exception = new BadCredentialsException("Invalid token type");
            }
            authenticationEntryPoint.commence(request, response, exception);
            return;
        }

        String realm = ((DefaultUserAuthenticationToken) auth).getRealm();
        request.setAttribute("realm", realm);
        secondFactorAuthenticationEntryPoint.commence(request, response, ex);
    }
}