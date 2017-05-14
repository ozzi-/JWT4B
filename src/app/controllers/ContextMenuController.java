package app.controllers;

import java.util.ArrayList;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

import javax.swing.JMenuItem;

import app.helpers.ConsoleOut;
import app.helpers.Strings;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

public class ContextMenuController implements Observer, IContextMenuFactory{

	private MenuItemListener menuItemListener;
	private String selectedText = null;
	private JWTSuiteTabController jstC;
	
	public ContextMenuController(JWTSuiteTabController jstC) {
		menuItemListener = new MenuItemListener();
		menuItemListener.addObserver(this); 
		this.jstC = jstC;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
		int[] selection = invocation.getSelectionBounds();
		byte iContext = invocation.getInvocationContext();
		if (selection != null) { // only if user currently is in an input field
			IHttpRequestResponse ihrr = invocation.getSelectedMessages()[0];
			// TODO https://github.com/mvetsch/JWT4B/issues/10 -> this issue needs to be fixed here
			if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
					|| iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
				selectedText=new String(ihrr.getRequest()).substring(selection[0], selection[1]);
			} else if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
					|| iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
				selectedText=new String(ihrr.getResponse()).substring(selection[0], selection[1]);
			} else {
				ConsoleOut.output("This context menu case (" + iContext + ")has not been covered yet!");
			}

			JMenuItem item = new JMenuItem(Strings.contextMenuString);
			item.addActionListener(menuItemListener);
			menuItems.add(item);
		}
		return menuItems;
	}

	@Override
	public void update(Observable o, Object arg) {
		// Menu Item Listener was clicked, notify the Suite Tab Controller
		jstC.contextActionJWT(selectedText,true);
	}

	public String getSelectedText() {
		return selectedText;
	}

}
