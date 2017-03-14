package app.controllers;

import java.util.ArrayList;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

import javax.swing.JMenuItem;

import app.Settings;
import app.helpers.ConsoleOut;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

public class ContextMenuController extends Observable implements Observer, IContextMenuFactory{

	private MenuItemListener menuItemListener;
	private String selectedText = null;
	
	public ContextMenuController(JWTSuiteTabController jstC) {
		menuItemListener = new MenuItemListener();
		menuItemListener.addObserver(this); 
		this.addObserver(jstC);
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
		int[] selection = invocation.getSelectionBounds();
		byte iContext = invocation.getInvocationContext();
		if (selection != null) { // only if user currently is in an input field
			IHttpRequestResponse ihrr = invocation.getSelectedMessages()[0];

			if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
					|| iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
				selectedText=new String(ihrr.getRequest()).substring(selection[0], selection[1]);
			} else if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
					|| iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
				selectedText=new String(ihrr.getResponse()).substring(selection[0], selection[1]);
			} else {
				ConsoleOut.output("This context menu case (" + iContext + ")has not been covered yet!");
			}

			JMenuItem item = new JMenuItem(Settings.contextMenuString);
			item.addActionListener(menuItemListener);
			menuItems.add(item);
		}
		return menuItems;
	}

	@Override
	public void update(Observable o, Object arg) {
		setChanged();
		notifyObservers(selectedText);
	}

	public String getSelectedText() {
		return selectedText;
	}

}
