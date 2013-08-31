package com.raltamirano.openfire.plugins.authentication;

import java.io.IOException;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Request;
import org.jivesoftware.openfire.auth.AuthFactory;
import org.jivesoftware.openfire.auth.AuthToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.misc.BASE64Decoder;

/**
 * An authentication-services servlet that allows programmatic access to the
 * security infrastructure proposed by Openfire.
 *
 * @author Rodrigo Altamirano
 */
public class AuthenticationServlet extends HttpServlet {

	private final static Logger log = LoggerFactory.getLogger(AuthenticationServlet.class);	
	private final static long serialVersionUID = 1L;

	private final static String AUTHENTICATION_TOKEN_ATTRIBUTE = "jive.admin.authToken";
		
	@Override
	protected void service(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {		
		String operation = request.getParameter("operation");
		
		if ("logon".equalsIgnoreCase(operation)) {
			boolean loginOK = false;
			String login = null;
			String password = null;

			String authorizationHeader = request.getHeader("Authorization");			
			if (authorizationHeader != null) {
				StringTokenizer tokenizer = new StringTokenizer(authorizationHeader);
				if (tokenizer.hasMoreTokens()) {
					String authenticationMethod = tokenizer.nextToken();

					if (Request.BASIC_AUTH.equalsIgnoreCase(authenticationMethod)) {
						String authenticationData = new String(new BASE64Decoder().decodeBuffer(tokenizer.nextToken()));

						int separatorPosition = authenticationData.indexOf(":");
						if (separatorPosition >= 0) {
							login = authenticationData.substring(0, separatorPosition);
							password = authenticationData.substring(separatorPosition + 1);

							AuthToken authenticationToken = null;
							try {
								authenticationToken = AuthFactory.authenticate(login, password);
								request.getSession().setAttribute(AUTHENTICATION_TOKEN_ATTRIBUTE, authenticationToken);
								loginOK = true;
							} catch (Throwable t) {
								loginOK = false;
								log.error("Error processing logon request for username [" + login + "]", t);
							}
						}		               
					}
				}
			}

			// If the logon did not succeded, signal the need for authentication to the client.
			if (!loginOK) {
				response.setStatus(401);
				response.setHeader("WWW-Authenticate", "Basic realm=\"Openfire\"");
			}
		} else if ("logout".equalsIgnoreCase(operation)) {
			request.getSession().removeAttribute(AUTHENTICATION_TOKEN_ATTRIBUTE);			
		} else if ("status".equalsIgnoreCase(operation)) {
			// Do nothing
		} else {
			throw new ServletException("Invalid operation: [" + operation + "]");
		}
		
		// Send the HTTP headers showing the current status
		AuthToken currentAuthenticationToken = null;
		try {
			currentAuthenticationToken = (AuthToken) request.getSession().getAttribute(AUTHENTICATION_TOKEN_ATTRIBUTE);
		} catch (Throwable t) { 
			currentAuthenticationToken = null;
		}
		
		if (currentAuthenticationToken != null) {
			response.setHeader("Openfire-AuthenticationStatus-IsAuthenticated", Boolean.TRUE.toString().toLowerCase());
			response.setHeader("Openfire-AuthenticationStatus-IsAnonymous", currentAuthenticationToken.isAnonymous() ? Boolean.TRUE.toString().toLowerCase() : Boolean.FALSE.toString().toLowerCase());
		} else {
			response.setHeader("Openfire-AuthenticationStatus-IsAuthenticated", Boolean.FALSE.toString().toLowerCase());
		}
	}
}
