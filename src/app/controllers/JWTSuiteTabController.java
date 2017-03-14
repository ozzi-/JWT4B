package app.controllers;

import java.awt.Component;

import javax.swing.JTabbedPane;

import app.Settings;
import burp.ITab;
import gui.JWTSuiteTab;

public class JWTSuiteTabController implements ITab {

	private JWTSuiteTab jsT;

	public JWTSuiteTabController() {
		jsT = new JWTSuiteTab();
	}

	public void setJWT(String jwt) {
		jsT.getTextField().setText(jwt);
	}

	@Override
	public String getTabCaption() {
		return Settings.tabname;
	}

	@Override
	public Component getUiComponent() {
		return jsT;
	}

	public JWTSuiteTab getJsT() {
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

}
