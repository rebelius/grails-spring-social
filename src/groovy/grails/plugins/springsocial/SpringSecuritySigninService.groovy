package grails.plugins.springsocial

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder

class SpringSecuritySigninService  {

    void signIn(String localUserId) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(localUserId, null, null))
    }
}
