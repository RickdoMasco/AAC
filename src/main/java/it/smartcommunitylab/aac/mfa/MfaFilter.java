package it.smartcommunitylab.aac.mfa;

import it.smartcommunitylab.aac.core.entrypoint.RealmAwarePathUriBuilder;
import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
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

    // Attributi di sessione per il flusso MFA
    static private final String MFA_FIRST_TOKEN = "MFA_FIRST_TOKEN";
    static private final String MFA_COMBINED_TOKEN = "MFA_COMBINED_TOKEN";
    static private final String MFA_COMPLETED = "MFA_COMPLETED";

    public MfaFilter(RealmManager realmManager, RealmAwarePathUriBuilder realmUriBuilder) {
        this.realmManager = realmManager;
        // Entry point per fallimenti auth iniziali (es. redirect a /login)
        this.authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint("/login");
        // Entry point per il redirect alla pagina di login del secondo fattore
        this.secondFactorAuthenticationEntryPoint = new RealmAwareAuthenticationEntryPoint("/login");
        this.secondFactorAuthenticationEntryPoint.setUseForward(false); // Forza redirect invece di forward
        this.secondFactorAuthenticationEntryPoint.setRealmUriBuilder(realmUriBuilder);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(true);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Salta MFA se non richiesta per il realm corrente o se l'auth non è un
        // DefaultUserAuthenticationToken
        if (isMfaSkipped(auth)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Se l'MFA è già stata completata in questa sessione, ripristina il token
        // combinato e procedi
        if (session.getAttribute(MFA_COMPLETED) != null) {
            restoreCombinedAuthentication(session);
            filterChain.doFilter(request, response);
            return;
        }

        // Nessun utente autenticato attivo procedi
        if (auth == null || !auth.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        // Avvia flusso MFA: salva token e redirect al secondo fattore
        if (session.getAttribute(MFA_FIRST_TOKEN) == null) {
            initiateMfaFlow(request, response, session, auth);
            return;
        }

        // Tentativo di secondo fattore: valida il token corrente rispetto a quello
        // salvato in sessione
        Authentication firstToken = (Authentication) session.getAttribute(MFA_FIRST_TOKEN);
        if (!isMfaValid(request, response, session, firstToken, auth)) {
            return;
        }

        // Entrambi i fattori validati: combina i token e finalizza l'accesso
        finalizeMfaFlow(session, (DefaultUserAuthenticationToken) firstToken, (DefaultUserAuthenticationToken) auth);
        filterChain.doFilter(request, response);
    }

    private boolean isMfaSkipped(Authentication auth) {

        if (!(auth instanceof DefaultUserAuthenticationToken))
            return false;

        Realm realm = realmManager.findRealm(((DefaultUserAuthenticationToken) auth).getRealm());

        return (realm != null && !realm.isMfaRequired());

    }

    private void restoreCombinedAuthentication(HttpSession session) {

        Authentication combined = (Authentication) session.getAttribute(MFA_COMBINED_TOKEN);

        if (combined != null)
            SecurityContextHolder.getContext().setAuthentication(combined);

    }

    private void initiateMfaFlow(HttpServletRequest request, HttpServletResponse response, HttpSession session,
            Authentication auth)
            throws IOException, ServletException {

        session.setAttribute(MFA_FIRST_TOKEN, auth);

        SecurityContextHolder.getContext().setAuthentication(null);

        request.changeSessionId();
        request.setAttribute("realm", ((DefaultUserAuthenticationToken) auth).getRealm());
        secondFactorAuthenticationEntryPoint.commence(request, response, null);
    }

    private boolean isMfaValid(HttpServletRequest request, HttpServletResponse response, HttpSession session,
            Authentication first, Authentication current) throws IOException, ServletException {

        if (!(first instanceof DefaultUserAuthenticationToken)
                || !(current instanceof DefaultUserAuthenticationToken)) {
            handleMfaFailure(session, request, response, "mfa_invalid_token_type");
            return false;
        }

        if (current.equals(first)) {
            handleMfaFailure(session, request, response, "mfa_duplicate_token");
            return false;
        }

        if (!((DefaultUserAuthenticationToken) first).getSubjectId()
                .equals(((DefaultUserAuthenticationToken) current).getSubjectId())) {
            handleMfaFailure(session, request, response, "mfa_subject_mismatch");
            return false;
        }

        return true;
    }

    private void handleMfaFailure(HttpSession session, HttpServletRequest request, HttpServletResponse response,
            String code)
            throws IOException, ServletException {

        session.removeAttribute(MFA_FIRST_TOKEN);
        SecurityContextHolder.clearContext();

        authenticationEntryPoint.commence(request, response, new BadCredentialsException(code));
    }

    private void finalizeMfaFlow(HttpSession session, DefaultUserAuthenticationToken ft,
            DefaultUserAuthenticationToken st) {

        DefaultUserAuthenticationToken combinedToken = new DefaultUserAuthenticationToken((Subject) ft.getPrincipal(),
                ft.getRealm(), ft.getAuthorities(), ft, st);

        SecurityContextHolder.getContext().setAuthentication(combinedToken);
        session.setAttribute(MFA_COMBINED_TOKEN, combinedToken);
        session.setAttribute(MFA_COMPLETED, true);
        session.removeAttribute(MFA_FIRST_TOKEN);
    }
}