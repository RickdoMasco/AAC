package it.smartcommunitylab.aac.mfa;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import it.smartcommunitylab.aac.core.auth.DefaultUserAuthenticationToken;
import it.smartcommunitylab.aac.core.auth.RealmAwareAuthenticationEntryPoint;
import it.smartcommunitylab.aac.model.Subject;
import org.springframework.security.web.AuthenticationEntryPoint;

public class MfaFilter extends OncePerRequestFilter {

    //TODO: remove hardcoded login path and use realm aware entry point
    private final AuthenticationEntryPoint authenticationEntryPoint = new RealmAwareAuthenticationEntryPoint("/login");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(true);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // verifica l'attributo MFA_COMPLETED che se è presente permette l'accesso e
        // blocca a logica del filtro per il rendirizzamento
        if (session.getAttribute("MFA_COMPLETED") != null) {
            Authentication combined = (Authentication) session.getAttribute("MFA_COMBINED_TOKEN");
            if (combined != null) {
                SecurityContextHolder.getContext().setAuthentication(combined);
            }
            filterChain.doFilter(request, response);
            return;
        }

        if (session.getAttribute("MFA_FIRST_TOKEN") == null) {
            // salvataggio primo token se attributo nella sessione
            if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
                session.setAttribute("MFA_FIRST_TOKEN", auth);
                System.out.println("Token 1: " + "\n" + session.getAttribute("MFA_FIRST_TOKEN"));

                SecurityContextHolder.getContext().setAuthentication(null);
                request.changeSessionId();

                authenticationEntryPoint.commence(request, response, null);
                return;
            }
        } else {
            // se il primo token è popolato allora si va alla logica che verifica il login
            // dopo il secondo login
            Authentication firstToken = (Authentication) session.getAttribute("MFA_FIRST_TOKEN");

            if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
                if (!auth.equals(firstToken)) {
                    if (firstToken instanceof DefaultUserAuthenticationToken
                            && auth instanceof DefaultUserAuthenticationToken) {

                        DefaultUserAuthenticationToken ft = (DefaultUserAuthenticationToken) firstToken;
                        DefaultUserAuthenticationToken st = (DefaultUserAuthenticationToken) auth;

                        System.out.println("Token 2: " + "\n" + st.toString());
                        
                        if (ft.getSubjectId().equals(st.getSubjectId())) {
                            session.setAttribute("MFA_COMPLETED", true);
                            
                            DefaultUserAuthenticationToken combinedToken = new DefaultUserAuthenticationToken(
                                (Subject) ft.getPrincipal(),
                                ft.getRealm(),
                                ft.getAuthorities(),
                                ft,
                                st);

                            System.out.println("Token unito: " + "\n" + combinedToken.toString());
                                
                            SecurityContextHolder.getContext().setAuthentication(combinedToken);
                            session.setAttribute("MFA_COMBINED_TOKEN", combinedToken);
                            session.removeAttribute("MFA_FIRST_TOKEN");

                            filterChain.doFilter(request, response);
                            return;
                        } else {
                            SecurityContextHolder.getContext().setAuthentication(null);
                            authenticationEntryPoint.commence(request, response,
                                    new org.springframework.security.authentication.BadCredentialsException(
                                            "invalid_mfa"));
                            return;
                        }
                    }
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}