package app.controllers;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Observable;

import app.helpers.NotifyTypes;

public class MenuItemListener extends Observable implements ActionListener   {
	@Override
	public void actionPerformed(ActionEvent arg0) {
		setChanged();
		notifyObservers(NotifyTypes.all);
	}
}
