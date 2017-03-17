package app.controllers;

import java.awt.Component;
import java.util.Observable;

import javax.swing.JTabbedPane;

import app.helpers.CustomJWTToken;
import app.helpers.Settings;
import burp.ITab;
import gui.JWTSuiteTab;

public class JWTSuiteTabController extends Observable implements ITab{

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

	// This method was copied from 
	// https://support.portswigger.net/customer/portal/questions/16743551-burp-extension-get-focus-on-tab-after-custom-menu-action
	public void selectJWTSuiteTab() {
		Component current = this.getUiComponent();
		do {
			current = current.getParent();
		} while (!(current instanceof JTabbedPane));

		JTabbedPane tabPane = (JTabbedPane) current;
		for (int i = 0; i < tabPane.getTabCount(); i++) {
			if (tabPane.getTitleAt(i).equals(this.getTabCaption()))
				tabPane.setSelectedIndex(i);
		}
	}

	public void contextAction(String jwts) {
		jsT.getInputField().setText(jwts);
		CustomJWTToken jwt = new CustomJWTToken(jwts);
		// TODO decoded token jsT.getOuputField().setText(jwt.getToken());
		selectJWTSuiteTab();
	}

}
