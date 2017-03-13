package app.controllers;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import app.helpers.ConsoleOut;

public class MenuItemListener implements ActionListener {

	private String selectedText;
	private JWTSuiteTabController jstC;

	public MenuItemListener(String selectedText, JWTSuiteTabController jstC) {
		this.selectedText = selectedText;
		this.jstC = jstC;
	}

	@Override
	public void actionPerformed(ActionEvent arg0) {
		ConsoleOut.output(selectedText);
		jstC.setJWT(selectedText);
		jstC.selectTab();
	}
}
