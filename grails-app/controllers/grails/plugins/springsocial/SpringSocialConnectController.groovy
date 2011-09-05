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

import grails.plugins.springsocial.connect.web.GrailsConnectSupport
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest
import org.springframework.social.connect.DuplicateConnectionException
import org.springframework.social.connect.support.OAuth1ConnectionFactory
import org.springframework.social.connect.support.OAuth2ConnectionFactory
import org.springframework.social.connect.web.ProviderSignInAttempt
import org.springframework.social.oauth1.OAuthToken
import org.springframework.web.context.request.RequestAttributes

class SpringSocialConnectController {

    private static final String DUPLICATE_CONNECTION_EXCEPTION_ATTRIBUTE = "_duplicateConnectionException"
    private static final String DUPLICATE_CONNECTION_ATTRIBUTE = "social.addConnection.duplicate"

    def connectionFactoryLocator
    def connectionRepository

    def webSupport = new GrailsConnectSupport()

    static allowedMethods = [connect: 'POST', oauthCallback: 'GET', disconnect: 'DELETE']

    def connect = {
        webSupport.home = g.createLink(uri: "/", absolute: true)
        def providerId = params.providerId
        def connectionFactory = connectionFactoryLocator.getConnectionFactory(providerId)
        def nativeWebRequest = new GrailsWebRequest(request, response, servletContext)
        def url = webSupport.buildOAuthUrl(connectionFactory, nativeWebRequest)
        redirect url: url
    }

    def oauthCallback = {
        def providerId = params.providerId
        def uriRedirect = session.ss_oauth_redirect_callback
        def config = SpringSocialUtils.config.get(providerId)
        def uri = uriRedirect ?: config.page.connectedHome
        def connectionFactory = connectionFactoryLocator.getConnectionFactory(providerId)
        def connection = webSupport.completeConnection(connectionFactory, new GrailsWebRequest(request, response, servletContext))

        addConnection(connection, connectionFactory, request)
        redirect(uri: uri)
    }

    def disconnect = {
      def providerId = session.providerId
    	def providerUserId = session.providerUserId
		ConnectionKey ck = new ConnectionKey(providerId,providerUserId);
		connectionRepository.removeConnection(ck);
		session.providerId=null
		session.providerUserId=null
		redirect(uri: SpringSocialUtils.config.postDisconnectUri)
    }

    private void addConnection(connection, connectionFactory, request) {
        try {
    		def provId=connection.getKey().getProviderId()
			def provUsrId=connection.getKey().getProviderUserId()
			session.providerId=provId
			session.providerUserId=provUsrId
			ConnectionKey ck = new ConnectionKey(provId,provUsrId);
			def ufd =UserConnection.findByProviderIdAndProviderUserId(provId,provUsrId)
			if (ufd){
				try{
					connectionRepository.getConnection(ck)
				
				}catch (Exception e){
					connectionRepository.addConnection(connection)
				}
			}else{
					connectionRepository.addConnection(connection)
			
			}
			//postConnect(connectionFactory, connection, request)
		} catch (DuplicateConnectionException e) {
			request.setAttribute(DUPLICATE_CONNECTION_ATTRIBUTE, e, RequestAttributes.SCOPE_SESSION);
		}
    }

    private String handleSignIn(connection, session) {
        String localUserId = usersConnectionRepository.findUserIdWithConnection(connection)
        if (localUserId == null) {
            def signInAttempt = new ProviderSignInAttempt(connection, connectionFactoryLocator, connectionRepository)
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
