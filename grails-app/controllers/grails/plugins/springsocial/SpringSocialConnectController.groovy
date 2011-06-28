/* Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package grails.plugins.springsocial

import javax.inject.Inject
import javax.inject.Provider
import org.springframework.social.connect.ConnectionFactoryLocator
import org.springframework.social.connect.ConnectionRepository
import org.springframework.social.connect.DuplicateConnectionException
import org.springframework.social.connect.support.OAuth1ConnectionFactory
import org.springframework.social.connect.support.OAuth2ConnectionFactory
import org.springframework.social.oauth1.AuthorizedRequestToken
import org.springframework.social.oauth1.OAuth1Parameters
import org.springframework.social.oauth1.OAuth1Version
import org.springframework.social.oauth1.OAuthToken
import org.springframework.social.oauth2.GrantType
import org.springframework.social.oauth2.OAuth2Parameters
import org.springframework.social.connect.web.ProviderSignInAttempt
import org.springframework.social.connect.web.ConnectSupport
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest

class SpringSocialConnectController {

    private static final String DUPLICATE_CONNECTION_EXCEPTION_ATTRIBUTE = "_duplicateConnectionException"

    def connectionFactoryLocator
    def usersConnectionRepository

    def webSupport = new ConnectSupport();

    @Inject
    Provider<ConnectionFactoryLocator> connectionFactoryLocatorProvider
    @Inject
    Provider<ConnectionRepository> connectionRepositoryProvider

    static allowedMethods = [withProvider: 'POST']

    def connect = {
        def providerId = params.providerId
        def connectionFactory = connectionFactoryLocator.getConnectionFactory(providerId)
        def url = webSupport.buildOAuthUrl(connectionFactory, new GrailsWebRequest(request, response, servletContext))
        println "redirecting to: ${url}"
        redirect url: url
    }

    String callbackUrl(provider) {
        g.createLink(mapping: 'springSocialConnect', params: [providerId: provider], absolute: true)
    }

    def oauthCallback = {
        def providerId = params.providerId
        def oauth_token = params.oauth_token
        def code = params.code
        def pam = oauth_token ?: code

        if (oauth_token) {
            def connectionFactory = connectionFactoryLocator.getConnectionFactory(providerId);
            def verifier = params.oauth_verifier
            def accessToken = connectionFactory.getOAuthOperations().exchangeForAccessToken(new AuthorizedRequestToken(extractCachedRequestToken(session), verifier), null)
            def connection = connectionFactory.createConnection(accessToken)
            addConnection(session, connectionFactory, connection)
            redirect(url: handleSignIn(connection, session))
        } else if (code) {
            render "providerId: ${providerId}, pam: ${pam}"
        }
    }

    def disconnect = {
        def providerId = params.providerId
        getConnectionRepository().removeConnectionsToProvider(providerId)
        redirect(uri: SpringSocialUtils.config.postDisconnectUri)
    }

    private void addConnection(session, connectionFactory, connection) {
        try {
            getConnectionRepository().addConnection(connection)
            //postConnect(connectionFactory, connection, request)
        } catch (DuplicateConnectionException e) {
            session.addAttribute(DUPLICATE_CONNECTION_EXCEPTION_ATTRIBUTE, e)
        }
    }

    private String handleSignIn(connection, session) {
        String localUserId = usersConnectionRepository.findUserIdWithConnection(connection)
        if (localUserId == null) {
            def signInAttempt = new ProviderSignInAttempt(connection, connectionFactoryLocatorProvider, connectionRepositoryProvider)
            session.setAttribute(ProviderSignInAttempt.SESSION_ATTRIBUTE, signInAttempt)
        }
        g.createLink(uri: SpringSocialUtils.config.postSignInUri)
    }

    private OAuthToken extractCachedRequestToken(session) {
        def requestToken = session.oauthToken
        session.removeAttribute('oauthToken')
        requestToken
    }

    private ConnectionRepository getConnectionRepository() {
        connectionRepositoryProvider.get()
    }
}
