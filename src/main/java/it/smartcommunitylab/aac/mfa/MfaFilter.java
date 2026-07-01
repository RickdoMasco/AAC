package it.smartcommunitylab.aac.mfa;

import it.smartcommunitylab.aac.core.entrypoint.RealmAwarePathUriBuilder;
import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
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

    static private final String MFA_FIRST_TOKEN = "MFA_FIRST_TOKEN";
    static private final String MFA_COMBINED_TOKEN = "MFA_COMBINED_TOKEN";

    private final String MFA_COMPLETED = "MFA_COMPLETED";

    public MfaFilter(RealmManager realmManager, RealmAwarePathUriBuilder realmUriBuilder) {
        this.realmManager = realmManager;
        this.authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint("/login");
        this.secondFactorAuthenticationEntryPoint = new RealmAwareAuthenticationEntryPoint("/login");
        this.secondFactorAuthenticationEntryPoint.setUseForward(false);
        this.secondFactorAuthenticationEntryPoint.setRealmUriBuilder(realmUriBuilder);
    }

    private void redirectFailedMFA(HttpSession session, HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(null);
        session.removeAttribute(MFA_FIRST_TOKEN);

        authenticationEntryPoint.commence(request, response,
                new org.springframework.security.authentication.BadCredentialsException(
                        "invalid_mfa"));

        // TODO: toast notification for error message

        return;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(true);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // skip if mfa check already completed by evalutating subject Id of the second
        // login with the first one
        if (session.getAttribute(MFA_COMPLETED) != null) {
            Authentication combined = (Authentication) session.getAttribute(MFA_COMBINED_TOKEN);
            if (combined != null) {
                SecurityContextHolder.getContext().setAuthentication(combined);
            }
            filterChain.doFilter(request, response);
            return;
        }

        // skip if no active auth
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            filterChain.doFilter(request, response);
            return;
        }

        // skip if realm does not require mfa
        // TODO: try to change mfa config so it's not hardcoded in the realm constructor
        if (auth instanceof DefaultUserAuthenticationToken) {
            DefaultUserAuthenticationToken token = (DefaultUserAuthenticationToken) auth;
            Realm realm = realmManager.findRealm(token.getRealm());
            if (realm != null && !realm.isMfaRequired()) {
                filterChain.doFilter(request, response);
                return;
            }
        }

        if (session.getAttribute(MFA_FIRST_TOKEN) == null) {
            // save first token
            session.setAttribute(MFA_FIRST_TOKEN, auth);
            // TODO: remove print
            System.out.println("Token 1: " + "\n" + session.getAttribute(MFA_FIRST_TOKEN));

            // remove authentication from the securitycontext
            SecurityContextHolder.getContext().setAuthentication(null);
            // change session id to avoid session fixation attacks
            request.changeSessionId();

            // preserve realm for second-factor redirect
            if (auth instanceof DefaultUserAuthenticationToken) {
                request.setAttribute("realm", ((DefaultUserAuthenticationToken) auth).getRealm());
            }

            // redirect to login page for the second factor
            secondFactorAuthenticationEntryPoint.commence(request, response, null);
            return;
        } else {
            // if the first token is already present, check if the second token is valid and matches the first one
            Authentication firstToken = (Authentication) session.getAttribute(MFA_FIRST_TOKEN);

            if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {

                // check if the second token is different from the first one
                if (!auth.equals(firstToken)) {

                    if (firstToken instanceof DefaultUserAuthenticationToken
                            && auth instanceof DefaultUserAuthenticationToken) {

                        // check if the subjectId of the first token is the same as the second one
                        DefaultUserAuthenticationToken ft = (DefaultUserAuthenticationToken) firstToken;
                        DefaultUserAuthenticationToken st = (DefaultUserAuthenticationToken) auth;
                        
                        // TODO: remove print
                        System.out.println("Token 2: " + "\n" + st.toString());

                        // check if the subjectId of the first token is the same as the second one
                        if (ft.getSubjectId().equals(st.getSubjectId())) {
                            session.setAttribute(MFA_COMPLETED, true);

                            // combine the two tokens into a new one and set it in the security context
                            DefaultUserAuthenticationToken combinedToken = new DefaultUserAuthenticationToken(
                                    (Subject) ft.getPrincipal(),
                                    ft.getRealm(),
                                    ft.getAuthorities(),
                                    ft,
                                    st);
                            
                            // TODO: remove print
                            System.out.println("Token unito: " + "\n" + combinedToken.toString());

                            SecurityContextHolder.getContext().setAuthentication(combinedToken);
                            session.setAttribute(MFA_COMBINED_TOKEN, combinedToken);

                            // remove the first token from the session
                            session.removeAttribute(MFA_FIRST_TOKEN);

                            filterChain.doFilter(request, response);
                            return;
                        } else {
                            redirectFailedMFA(session, request, response);
                            return;
                        }
                    } else {
                        redirectFailedMFA(session, request, response);
                        return;
                    }
                } else {
                    redirectFailedMFA(session, request, response);
                    return;
                }
            } else {
                redirectFailedMFA(session, request, response);
                return;
            }
        }
    }
}