/******************************************************************************* 
 * Copyright (c) 2016 Red Hat, Inc. 
 * Distributed under license by Red Hat, Inc. All rights reserved. 
 * This program is made available under the terms of the 
 * Eclipse Public License v1.0 which accompanies this distribution, 
 * and is available at http://www.eclipse.org/legal/epl-v10.html 
 * 
 * Contributors: 
 * Red Hat, Inc. - initial API and implementation 
 ******************************************************************************/
package com.openshift.internal.restclient.okhttp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;

import com.openshift.internal.restclient.DefaultClient;
import com.openshift.internal.restclient.authorization.AuthorizationDetails;
import com.openshift.internal.util.URIUtils;
import com.openshift.restclient.IClient;
import com.openshift.restclient.authorization.IAuthorizationContext;
import com.openshift.restclient.authorization.IAuthorizationDetails;
import com.openshift.restclient.authorization.UnauthorizedException;
import com.openshift.restclient.http.IHttpConstants;

import okhttp3.Authenticator;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Request.Builder;
import okhttp3.Response;
import okhttp3.Route;

/**
 * OkHttp Authenticator implementations for OpenShift 3
 * @author jeff.cantrill
 *
 */
public class OpenShiftAuthenticator implements Authenticator, IHttpConstants{
	
	public static final String ACCESS_TOKEN = "access_token";
	private static final String AUTH_ATTEMPTS = "X-OPENSHIFT-AUTH-ATTEMPTS";
	private static final String CSRF_TOKEN = "X-CSRF-Token";
	private static final String ERROR = "error";
	private static final String ERROR_DETAILS = "error_details";
	private static final Logger LOGGER = Logger.getLogger(OpenShiftAuthenticator.class.getName());

	private Collection<IChallangeHandler> challangeHandlers = new ArrayList<>();
	private OkHttpClient okClient;
	private IClient client;
	
	@Override
	public Request authenticate(Route route, Response response) throws IOException {
		if(unauthorizedForCluster(response)){
			String requestUrl = response.request().url().toString();
			String url = route.address().url().toString() + "oauth/authorize?response_type=token&client_id=openshift-challenging-client";
			LOGGER.fine("Requesting authentication on " + url);
            Request authRequest = new Request.Builder()
					.addHeader(CSRF_TOKEN, "1")
					.url(url)
					.build();
			try (
				Response authResponse = tryAuth(authRequest)){
		         LOGGER.fine("Response to authentication is: " + authResponse);
				if(authResponse.isSuccessful()) {
					String token = extractAndSetAuthContextToken(authResponse);
					String bearer = String.format("%s %s", IHttpConstants.AUTHORIZATION_BEARER, token);
	                LOGGER.fine("Bearer is: " + bearer);
                    return response.request().newBuilder()
							.header(IHttpConstants.PROPERTY_AUTHORIZATION, bearer)
							.build();
				}
			}
			throw new UnauthorizedException(captureAuthDetails(requestUrl), ResponseCodeInterceptor.getStatus(response.body().string()));
		}

		return null;
	}
	
	private boolean unauthorizedForCluster(Response response) {
		String requestHost = response.request().url().host();
        int responseCode = response.code();
        LOGGER.fine("Request host  is: " + requestHost + " and response code: " + responseCode);
        String baseHost = client.getBaseURL().getHost();
        boolean unauthorized = (responseCode == STATUS_UNAUTHORIZED) && baseHost.equals(requestHost);
        LOGGER.fine("Request is unauthorized: " + unauthorized);    
        return unauthorized;
	}
	
	private Response tryAuth(Request authRequest) throws IOException {
        System.out.println("##########  authRequest:  details:" + authRequest);
        LOGGER.fine("authRequest:  details:" + authRequest);
		return okClient
		.newBuilder()
		.authenticator(new Authenticator() {
			
			@Override
			public Request authenticate(Route route, Response response) throws IOException {
				if(StringUtils.isNotBlank(response.request().header(AUTH_ATTEMPTS))) {
				    System.out.println("##########  Response with not blank AUTH_ATTEMPTS :  response:" + response);
			        LOGGER.fine("Response with not blanch AUTH_ATTEMPTS :  response:" + response);
					return null;
				}
				if(StringUtils.isNotBlank(response.header(IHttpConstants.PROPERTY_WWW_AUTHENTICATE))) {
				    System.out.println("##########  Response with not blank PROPERTY_WWW_AUTHENTICATE :  response:" + response);
                    LOGGER.fine("Response with not blanch PROPERTY_WWW_AUTHENTICATE :  response:" + response);
				    for (IChallangeHandler challangeHandler : challangeHandlers) {
						if(!challangeHandler.canHandle(response.headers())) {
							Builder requestBuilder = response.request().newBuilder()
									.header(AUTH_ATTEMPTS, "1");
							return challangeHandler.handleChallange(requestBuilder).build();
						}
					}
				}
				return null;
			}
		})
		.followRedirects(false)
		.followRedirects(false)
		.build()
		.newCall(authRequest).execute();
	}
	
	private IAuthorizationDetails captureAuthDetails(String url) {
		IAuthorizationDetails details = null;
		Map<String, String> pairs = URIUtils.splitFragment(url);
        System.out.println("#############################: "+ pairs);
		LOGGER.fine("Error details:" + pairs);
		if (pairs.containsKey(ERROR)) {
			details = new AuthorizationDetails(pairs.get(ERROR), pairs.get(ERROR_DETAILS));
		}
		return details;
	}
	
	private String extractAndSetAuthContextToken(Response response) {
        LOGGER.fine("Extracting response and setting token....");

		String token = null;
		Map<String, String> pairs = URIUtils.splitFragment(response.header(PROPERTY_LOCATION));
        LOGGER.fine("AuthContextToken details:" + pairs);
		if (pairs.containsKey(ACCESS_TOKEN)) {
			token = pairs.get(ACCESS_TOKEN);
	        LOGGER.fine("Token find in response under " + ACCESS_TOKEN + " key with value: " + token);
			IAuthorizationContext authContext = client.getAuthorizationContext();
			if(authContext != null) {
				authContext.setToken(token);
			} else {
			    LOGGER.severe("ERROR: AutheContext is null !!!");
			}
		} else {
	        LOGGER.severe("ERROR: No token found in response !!!");
		}
		return token;
	}
	

	public void setOkClient(OkHttpClient okClient) {
		this.okClient = okClient;
	}

	public void setClient(DefaultClient client) {
		this.client = client;
		challangeHandlers.clear();
		IAuthorizationContext authorizationContext = client.getAuthorizationContext();
        System.out.println("############### Auth Context  ##############: "+ authorizationContext);
        LOGGER.fine("AuthContext:  details:" + authorizationContext);  
        BasicChallangeHandler challenge = new BasicChallangeHandler(authorizationContext);
        System.out.println("############### Auth BasicChallangeHandler  ##############: " + challenge);
        LOGGER.fine("BasicChallangeHandler:  challenge:" + challenge);  
        
        challangeHandlers.add(challenge);
	}

}