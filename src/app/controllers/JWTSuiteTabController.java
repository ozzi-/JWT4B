package app.controllers;

import java.awt.Component;
import java.util.Observable;

import javax.swing.JTabbedPane;

import app.helpers.ConsoleOut;
import app.helpers.CustomJWTToken;
import app.helpers.Settings;
import burp.ITab;
import gui.JWTSuiteTab;

public class JWTSuiteTabController extends Observable implements ITab{

	private JWTSuiteTab jsT;

	public JWTSuiteTabController() {
		jsT = new JWTSuiteTab(this);
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
		jwts=jwts.replace("Authorization:","");
		jwts=jwts.replace("Bearer","");
		jwts=jwts.replaceAll("\\s","");
		jsT.getInputField().setText(jwts);
		try{
			CustomJWTToken jwt = new CustomJWTToken(jwts);
			jsT.getOuputField().setText(ReadableTokenFormat.getReadableFormat(jwt));
		}catch (Exception e){
			ConsoleOut.output(e.getMessage());
		}
		selectJWTSuiteTab();
	}


}
