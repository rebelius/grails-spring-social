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

import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest
import org.springframework.social.connect.DuplicateConnectionException
import org.springframework.social.connect.web.ConnectSupport
import org.springframework.social.connect.web.ProviderSignInAttempt
import org.springframework.social.oauth1.OAuthToken
import org.springframework.web.context.request.RequestAttributes
import org.springframework.social.connect.support.OAuth2ConnectionFactory
import org.springframework.social.connect.support.OAuth1ConnectionFactory

class SpringSocialConnectController {

    private static final String DUPLICATE_CONNECTION_EXCEPTION_ATTRIBUTE = "_duplicateConnectionException"
    private static final String DUPLICATE_CONNECTION_ATTRIBUTE = "social.addConnection.duplicate"

    def connectionFactoryLocator
    def connectionRepository

    def webSupport = new ConnectSupport();

    static allowedMethods = [connect: 'POST', oauthCallback: 'GET', disconnect: 'DELETE']

    def connect = {
        def providerId = params.providerId
        def connectionFactory = connectionFactoryLocator.getConnectionFactory(providerId)
        def url = webSupport.buildOAuthUrl(connectionFactory, new GrailsWebRequest(request, response, servletContext))
        println "redirecting to: ${url}"
        redirect url: url
    }

    def oauthCallback = {
        def providerId = params.providerId
        def oauth_token = params.oauth_token
        def code = params.code
        def nativeWebRequest = new GrailsWebRequest(request, response, servletContext)

        if (oauth_token) {
            OAuth1ConnectionFactory<?> connectionFactory = (OAuth1ConnectionFactory<?>) connectionFactoryLocator.getConnectionFactory(providerId)
            def connection = webSupport.completeConnection(connectionFactory, nativeWebRequest)
            addConnection(connection, connectionFactory, request)
            render "OAuth1ConnectionFactory"

        } else if (code) {
            OAuth2ConnectionFactory<?> connectionFactory = (OAuth2ConnectionFactory<?>) connectionFactoryLocator.getConnectionFactory(providerId)
            def connection = webSupport.completeConnection(connectionFactory, nativeWebRequest)
            addConnection(connection, connectionFactory, request)
            render "OAuth2ConnectionFactory"
        }
    }

    def disconnect = {
        def providerId = params.providerId
        getConnectionRepository().removeConnectionsToProvider(providerId)
        redirect(uri: SpringSocialUtils.config.postDisconnectUri)
    }

    private void addConnection(connection, connectionFactory, request) {
        try {
            connectionRepository.addConnection(connection)
            //postConnect(connectionFactory, connection, request)
        } catch (DuplicateConnectionException e) {
            request.setAttribute(DUPLICATE_CONNECTION_ATTRIBUTE, e, RequestAttributes.SCOPE_SESSION);
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

}
