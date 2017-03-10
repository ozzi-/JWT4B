package app.controllers;

import java.awt.Component;

import app.Settings;
import burp.ITab;
import gui.JWTSuiteTab;

public class JWTSuiteTabController implements ITab {
	
	private JWTSuiteTab jsT;

	public JWTSuiteTabController() {
		jsT = new JWTSuiteTab();
	}

	@Override
	public String getTabCaption() {
		return Settings.tabname;
	}

	@Override
	public Component getUiComponent() {
		return jsT;
	}

}
