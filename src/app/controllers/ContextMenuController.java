package app.controllers;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import app.Settings;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;

public class ContextMenuController implements IContextMenuFactory {

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
		int[] selection = invocation.getSelectionBounds();
		if (selection != null) { // only if text is selected inside a message
			JMenuItem item = new JMenuItem(Settings.contextMenuString);
			// item.addActionListener(arg0); TODO
			menuItems.add(item);
		}
		return menuItems; 
	}

}
