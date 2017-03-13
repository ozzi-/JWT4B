package app.controllers;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import app.Settings;
import app.helpers.ConsoleOut;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;

public class ContextMenuController implements IContextMenuFactory {

	private JWTSuiteTabController jstC;

	public ContextMenuController(JWTSuiteTabController jstC) {
		this.jstC = jstC;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
		int[] selection = invocation.getSelectionBounds();
		byte iContext = invocation.getInvocationContext();
		if (selection != null) { // only if user currently is in an input field
			String selectedText="";
			if(iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST){
				selectedText = new String(invocation.getSelectedMessages()[0].getRequest()).substring(selection[0], selection[1]);
			}else if(iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE  || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE){
				selectedText = new String(invocation.getSelectedMessages()[0].getResponse()).substring(selection[0], selection[1]);
			}else{
				ConsoleOut.output("This context menu case ("+iContext+")has not been covered yet!");
			}
			JMenuItem item = new JMenuItem(Settings.contextMenuString);
			item.addActionListener(new MenuItemListener(selectedText,jstC));
			menuItems.add(item);
		}
		return menuItems; 
	}

}
