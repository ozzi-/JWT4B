package app.controllers;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import app.helpers.MessageBean;

public class MenuItemListener implements ActionListener {

	private MessageBean bean;

	public MenuItemListener(MessageBean bean) {
		this.bean = bean;
	}
	
	@Override
	public void actionPerformed(ActionEvent e) {
		bean.setMessage("menuitem");
	}
}
