/*******************************************************************************
 * Copyright (c) 2015 Red Hat, Inc. Distributed under license by Red Hat, Inc.
 * All rights reserved. This program is made available under the terms of the
 * Eclipse Public License v1.0 which accompanies this distribution, and is
 * available at http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors: Red Hat, Inc. - initial API and implementation
 ******************************************************************************/
package com.openshift.restclient.authorization;

import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;

import com.openshift.restclient.OpenShiftException;
import com.openshift.restclient.model.IStatus;

/**
 * @author Jeff Cantrill
 */
public class UnauthorizedException extends OpenShiftException {

	private static final long serialVersionUID = -3999801367045252906L;
	private static final String MSG_BASE = "Unauthorized to access resource.";
	  private static final Logger LOGGER = Logger.getLogger(UnauthorizedException.class.getName());
	private String message;
	private IStatus status;
	private IAuthorizationDetails details;
	
	public UnauthorizedException(IAuthorizationDetails details) {
		this(details, null);
	}

	public UnauthorizedException(IAuthorizationDetails details, IStatus status) {
		super(String.format("%s See the authorization details for additional information or contact your system administrator.", MSG_BASE));
		this.status = status;
		this.details = details;
		System.out.println("###### Build exception from details: " + details);
        LOGGER.fine("Build exception from details: " + details);
		if(details != null) {
			if(StringUtils.isNotBlank(details.getScheme())){
				String messageFormat = "%s You can access the server using %s authentication. Details: %s\n\t parent message: %s";
                message = String.format(messageFormat, MSG_BASE, details.getScheme(), details.getMessage(),super.getMessage());
                System.out.println("###### Build exception with message: " + message);
                LOGGER.fine("Build exception with message: " + message);
			}else {
				message = details.getMessage();
                System.out.println("###### Build exception with message: " + message);
                LOGGER.fine("Build exception with message: " + message);
			}

		}else {
			message = super.getMessage();
            System.out.println("###### Build exception with message: " + message);
            LOGGER.fine("Build exception with message: " + message);
		}

	}
	
	public IAuthorizationDetails getAuthorizationDetails() {
		return details;
	}

	@Override
	public String getMessage() {
		return message;
	}

	@Override
	public IStatus getStatus() {
		return this.status;
	}
	
	

}
