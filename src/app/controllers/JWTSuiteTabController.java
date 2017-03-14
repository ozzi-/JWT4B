package app.controllers;

import java.awt.Component;
import java.util.Observable;
import java.util.Observer;

import javax.swing.JTabbedPane;

import app.Settings;
import burp.ITab;
import gui.JWTSuiteTab;

public class JWTSuiteTabController extends Observable implements ITab, Observer {

	private JWTSuiteTab jsT;

	public JWTSuiteTabController() {
		jsT = new JWTSuiteTab(this);
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

	@Override
	public void update(Observable o, Object arg) {
		String selectedText = (String)arg;
		// TODO do checks for logic / decoding
		setChanged();
		notifyObservers(selectedText);
	}

}
