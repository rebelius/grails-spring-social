package grails.plugins.springsocial

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.social.connect.signin.web.SignInService

class SpringSecuritySigninService implements SignInService {

    void signIn(String localUserId) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(localUserId, null, null))
    }
}
