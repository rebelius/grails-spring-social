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
import org.springframework.social.connect.UsersConnectionRepository
import org.springframework.social.connect.support.OAuth1ConnectionFactory
import org.springframework.social.connect.support.OAuth2ConnectionFactory
import org.springframework.social.oauth1.AuthorizedRequestToken
import org.springframework.social.oauth1.OAuth1Parameters
import org.springframework.social.oauth1.OAuth1Version
import org.springframework.social.oauth1.OAuthToken
import org.springframework.social.oauth2.GrantType
import org.springframework.social.oauth2.OAuth2Parameters
import org.springframework.social.connect.Connection
import org.springframework.social.connect.signin.web.ProviderSignInAttempt
import org.springframework.web.context.request.WebRequest

class SpringSocialProviderSignInController {
    @Inject
    Provider<ConnectionFactoryLocator> connectionFactoryLocatorProvider

    UsersConnectionRepository usersConnectionRepository
    @Inject
    Provider<ConnectionRepository> connectionRepositoryProvider
    def signInService

    def withProvider = {
        def providerId = params.providerId
        def connectionFactory = getConnectionFactoryLocator().getConnectionFactory(providerId)
        if (connectionFactory instanceof OAuth1ConnectionFactory) {
            if (params.ss_oauth_return_url) {
                session.ss_oauth_return_url = params.ss_oauth_return_url
            }
            def oauth1Ops = connectionFactory.getOAuthOperations()
            def requestToken = oauth1Ops.fetchRequestToken(callbackUrl(providerId), null)
            session.oauthToken = requestToken
            String authenticateUrl = oauth1Ops.buildAuthenticateUrl(requestToken.getValue(), oauth1Ops.getVersion() == OAuth1Version.CORE_10 ? new OAuth1Parameters(callbackUrl(providerId)) : OAuth1Parameters.NONE)
            redirect url: authenticateUrl
        } else if (connectionFactory instanceof OAuth2ConnectionFactory) {
            def oauth2Ops = connectionFactory.getOAuthOperations()
            String authenticateUrl = oauth2Ops.buildAuthenticateUrl(GrantType.AUTHORIZATION_CODE, new OAuth2Parameters(callbackUrl(providerId), request.getParameter("scope")))
            redirect url: authenticateUrl
        } else {
            render "return handleSignInWithConnectionFactory(connectionFactory, request)"
        }
    }

    def oauthCallback = {
        def providerId = params.providerId
        def oauth_token = params.oauth_token
        def code = params.code
        def pam = oauth_token ?: code

        if (oauth_token) {
            def verifier = params.oauth_verifier

            def connectionFactory = getConnectionFactoryLocator().getConnectionFactory(providerId)
            def accessToken = connectionFactory.getOAuthOperations().exchangeForAccessToken(new AuthorizedRequestToken(extractCachedRequestToken(session), verifier), null)
            def connection = connectionFactory.createConnection(accessToken)
            //return handleSignIn(connection, request);
            redirect(url: handleSignIn(connection, session))
        } else if (code) {
            render "providerId: ${providerId}, pam: ${pam}"
        }
    }

    private ConnectionFactoryLocator getConnectionFactoryLocator() {
        return connectionFactoryLocatorProvider.get();
    }

    String callbackUrl(provider) {
        g.createLink(mapping: 'springSocialSignIn', params: [providerId: provider], absolute: true)
    }


    private OAuthToken extractCachedRequestToken(session) {
        def requestToken = session.oauthToken
        session.removeAttribute('oauthToken')
        requestToken
    }

    private void addConnection(session, connectionFactory, connection) {
        try {
            getConnectionRepository().addConnection(connection)
            //postConnect(connectionFactory, connection, request)
        } catch (DuplicateConnectionException e) {
            session.addAttribute(DUPLICATE_CONNECTION_EXCEPTION_ATTRIBUTE, e)
        }
    }

    private ConnectionRepository getConnectionRepository() {
        connectionRepositoryProvider.get()
    }

    private String handleSignIn(connection, session) {
        String localUserId = usersConnectionRepository.findUserIdWithConnection(connection)
        if (localUserId == null) {
            def signInAttempt = new ProviderSignInAttempt(connection, connectionFactoryLocatorProvider, connectionRepositoryProvider);
            session.setAttribute(ProviderSignInAttempt.SESSION_ATTRIBUTE, signInAttempt)
        } else {
            signInService.signIn(localUserId)
        }
        session.ss_last_user_profile = connection.fetchUserProfile()
        def postSignInUri = session.ss_oauth_return_url ?: SpringSocialUtils.config.postSignInUri
        println "redirecting to: $postSignInUri"
        postSignInUri
    }
}