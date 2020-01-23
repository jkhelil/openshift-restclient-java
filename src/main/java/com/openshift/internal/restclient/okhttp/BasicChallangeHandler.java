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

import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;

import com.openshift.restclient.authorization.IAuthorizationContext;
import com.openshift.restclient.http.IHttpConstants;
import com.openshift.restclient.utils.Base64Coder;

import okhttp3.Headers;
import okhttp3.Request.Builder;

/**
 * 
 * @author jeff.cantrill
 *
 */
public class BasicChallangeHandler implements IChallangeHandler{
    private static final Logger LOGGER = Logger.getLogger(BasicChallangeHandler.class.getName());

	private IAuthorizationContext context;

	public BasicChallangeHandler(IAuthorizationContext context) {
		this.context = context;
	}

	@Override
	public boolean canHandle(Headers headers) {
	    LOGGER.fine("can we handle " + headers + "?");
		return OpenShiftAuthenticator.AUTHORIZATION_BASIC.equalsIgnoreCase(headers.get(OpenShiftAuthenticator.PROPERTY_WWW_AUTHENTICATE));
	}

	@Override
	public Builder handleChallange(Builder builder) {
		StringBuilder value = new StringBuilder();
		if(StringUtils.isNotBlank(context.getUserName())) {
            LOGGER.fine("Username" + context.getUserName() );
			value.append(context.getUserName()).append(":");
		}
		if(StringUtils.isNotBlank(context.getPassword())) {
            LOGGER.fine("Password" + context.getPassword() );
			value.append(context.getPassword());
		}
		String basicAuthEncoded = Base64Coder.encode(value.toString());
        LOGGER.fine("Basic Auth:" + basicAuthEncoded );
        return builder.header(OpenShiftAuthenticator.PROPERTY_AUTHORIZATION, IHttpConstants.AUTHORIZATION_BASIC + " " + basicAuthEncoded);
	}
	
}