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
            System.out.println("###### Requesting authentication on " + url);
			LOGGER.fine("Requesting authentication on " + url);
            Request authRequest = new Request.Builder()
					.addHeader(CSRF_TOKEN, "1")
					.url(url)
					.build();
			// WARNING: THIS IS A TRY-WITH-RESOURCES STATEMENT NOT A TRADITIONAL TRY-CATCH
            // ARGGGHHH
//            try (
//				Response authResponse = tryAuth(authRequest);){
//		         System.out.println("###### Response to authentication is: " + authResponse);
//                 LOGGER.fine("Response to authentication is: " + authResponse);
//				if(authResponse.isSuccessful()) {
//					String token = extractAndSetAuthContextToken(authResponse);
//					String bearer = String.format("%s %s", IHttpConstants.AUTHORIZATION_BEARER, token);
//	                System.out.println("###### Bearer is: " + bearer);
//                    LOGGER.fine("Bearer is: " + bearer);
//                    return response.request().newBuilder()
//							.header(IHttpConstants.PROPERTY_AUTHORIZATION, bearer)
//							.build();
//				}
//			} catch (Exception e) {
//			    e.printStackTrace();
//	            throw new UnauthorizedException(captureAuthDetails(requestUrl), ResponseCodeInterceptor.getStatus(response.body().string()));
//			}
            
            Response authResponse = null;
            try {
                authResponse = tryAuth(authRequest);
                System.out.println("###### Response to authentication is: " + authResponse);
                LOGGER.fine("Response to authentication is: " + authResponse);
                if (authResponse.isSuccessful()) {
                    String token = extractAndSetAuthContextToken(authResponse);
                    String bearer = String.format("%s %s", IHttpConstants.AUTHORIZATION_BEARER, token);
                    System.out.println("###### Bearer is: " + bearer);
                    LOGGER.fine("Bearer is: " + bearer);
                    return response.request().newBuilder().header(IHttpConstants.PROPERTY_AUTHORIZATION, bearer)
                            .build();
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new UnauthorizedException(captureAuthDetails(requestUrl),
                        ResponseCodeInterceptor.getStatus(response.body().string()));
            } finally {
                if( authResponse != null ) { 
                    try { authResponse.close(); } catch( Exception e ) { e.printStackTrace(); throw e; }
                }
            }

        }

		return null;
	}
	
	private boolean unauthorizedForCluster(Response response) {
		String requestHost = response.request().url().host();
        int responseCode = response.code();
        System.out.println("###### Request host  is: " + requestHost + " and response code: " + responseCode);
        LOGGER.fine("Request host  is: " + requestHost + " and response code: " + responseCode);
        String baseHost = client.getBaseURL().getHost();
        boolean unauthorized = (responseCode == STATUS_UNAUTHORIZED) && baseHost.equals(requestHost);
        System.out.println("###### Request is unauthorized: " + unauthorized);    
        LOGGER.fine("Request is unauthorized: " + unauthorized);    
        return unauthorized;
	}
	
	private Response tryAuth(Request authRequest) throws IOException {
        System.out.println("###### authRequest:  details:" + authRequest);
        LOGGER.fine("authRequest:  details:" + authRequest);
		return okClient
		.newBuilder()
		.authenticator(new Authenticator() {
			
			@Override
			public Request authenticate(Route route, Response response) throws IOException {
				String attemptsHeader = response.request().header(AUTH_ATTEMPTS);
                if(StringUtils.isNotBlank(attemptsHeader)) {
				    System.out.println("##########  Response with not blank AUTH_ATTEMPTS :  response:" + response);
                    LOGGER.fine("Response with not blanch AUTH_ATTEMPTS :  response:" + response);
                    System.out.println("########## About to return null Request: AUTH_ATTEMPTS not blank");
                    LOGGER.fine("About to return null Request: AUTH_ATTEMPTS not blank");
					return null;
				}
				String authenticateHeader = response.header(IHttpConstants.PROPERTY_WWW_AUTHENTICATE);
                if(StringUtils.isNotBlank(authenticateHeader)) {
                    System.out.println("###### Response with not blank PROPERTY_WWW_AUTHENTICATE :  response:" + response);
                    LOGGER.fine("Response with not blanch PROPERTY_WWW_AUTHENTICATE :  response:" + response);
				    for (IChallangeHandler challangeHandler : challangeHandlers) {
						if(!challangeHandler.canHandle(response.headers())) {
							Builder requestBuilder = response.request().newBuilder()
									.header(AUTH_ATTEMPTS, "1");
							return challangeHandler.handleChallange(requestBuilder).build();
						}
					}
				}
                System.out.println("########## About to return null Request: AUTH_ATTEMPTS and WWW-AUTHENTICATE are blank");
                LOGGER.fine("About to return null Request: AUTH_ATTEMPTS and WWW-AUTHENTICATE are blank");
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
		System.out.println("###### Error details:" + pairs);
        LOGGER.fine("Error details:" + pairs);
		if (pairs.containsKey(ERROR)) {
			details = new AuthorizationDetails(pairs.get(ERROR), pairs.get(ERROR_DETAILS));
		}
		return details;
	}
	
	private String extractAndSetAuthContextToken(Response response) {
        System.out.println("###### Extracting response and setting token....");
        LOGGER.fine("Extracting response and setting token....");

		String token = null;
		Map<String, String> pairs = URIUtils.splitFragment(response.header(PROPERTY_LOCATION));
        System.out.println("###### AuthContextToken details:" + pairs);
        LOGGER.fine("AuthContextToken details:" + pairs);
		if (pairs.containsKey(ACCESS_TOKEN)) {
			token = pairs.get(ACCESS_TOKEN);
	        System.out.println("###### Token find in response under " + ACCESS_TOKEN + " key with value: " + token);
            LOGGER.fine("Token find in response under " + ACCESS_TOKEN + " key with value: " + token);
			IAuthorizationContext authContext = client.getAuthorizationContext();
			if(authContext != null) {
				authContext.setToken(token);
			} else {
			    System.out.println("###### ERROR: AutheContext is null !!!");
                LOGGER.severe("ERROR: AutheContext is null !!!");
			}
		} else {
	        System.out.println("###### ERROR: No token found in response !!!");
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
        System.out.println("###### AuthContext:  details:" + authorizationContext);  
        LOGGER.fine("AuthContext:  details:" + authorizationContext);  
        BasicChallangeHandler challenge = new BasicChallangeHandler(authorizationContext);
        System.out.println("############### Auth BasicChallangeHandler  ##############: " + challenge);
        System.out.println("###### BasicChallangeHandler:  challenge:" + challenge);  
        LOGGER.fine("BasicChallangeHandler:  challenge:" + challenge);  
        
        challangeHandlers.add(challenge);
	}

}
