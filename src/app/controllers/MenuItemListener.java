package app.controllers;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Observable;

public class MenuItemListener extends Observable implements ActionListener   {
	@Override
	public void actionPerformed(ActionEvent arg0) {
		setChanged();
		notifyObservers();
	}
}
