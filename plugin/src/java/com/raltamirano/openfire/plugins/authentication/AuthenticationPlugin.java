package com.raltamirano.openfire.plugins.authentication;

import java.io.File;

import org.jivesoftware.admin.AuthCheckFilter;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;

/**
 * Openfire Authentication plugin class.
 *
 * @author Rodrigo Altamirano
 */
public class AuthenticationPlugin implements Plugin {

	private final static String SERVLET_URL = "authentication/authentication";

	@Override
	public void initializePlugin(PluginManager manager, File pluginDirectory) {
		AuthCheckFilter.addExclude(SERVLET_URL);
	}

	@Override
	public void destroyPlugin() {
		AuthCheckFilter.removeExclude(SERVLET_URL);
	}
}
