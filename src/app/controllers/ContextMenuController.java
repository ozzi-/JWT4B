package app.controllers;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import app.helpers.MessageBean;
import app.helpers.Output;
import app.helpers.Strings;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

public class ContextMenuController implements IContextMenuFactory{

	private MenuItemListener menuItemListener;
	private String selectedText = null;
	
	public ContextMenuController(JWTSuiteTabController jstC) {	
		MessageBean bean = new MessageBean();
		bean.addPropertyChangeListener(new PropertyChangeListener() {
			@Override
			public void propertyChange(PropertyChangeEvent evt) {
				if(evt.getNewValue().equals("menuitem")) {
					jstC.contextActionJWT(selectedText,true);					
				}
			}
		});
		menuItemListener = new MenuItemListener(bean);
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
				Output.outputError("This context menu case (" + iContext + ") has not been covered yet!");
			}

			JMenuItem item = new JMenuItem(Strings.contextMenuString);
			item.addActionListener(menuItemListener);
			menuItems.add(item);
		}
		return menuItems;
	}

	public String getSelectedText() {
		return selectedText;
	}
}
