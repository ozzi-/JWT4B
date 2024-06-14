package burp;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext;

import app.controllers.JWTSuiteTabController;
import model.Strings;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class JWT4BContextMenuItemsProvider implements ContextMenuItemsProvider {
	private final JWTSuiteTabController jstC;

	public JWT4BContextMenuItemsProvider(JWTSuiteTabController jstC) {
		this.jstC = jstC;
	}

	@Override
	public List<Component> provideMenuItems(ContextMenuEvent event) {
		List<Component> menuItemList = new ArrayList<>();

		// editor and selection need to be present
		if (event.messageEditorRequestResponse().isPresent() && event.messageEditorRequestResponse().get().selectionOffsets().isPresent()) {
			HttpRequestResponse requestResponse = event.messageEditorRequestResponse().get().requestResponse();

			SelectionContext selectionContext = event.messageEditorRequestResponse().get().selectionContext();
			int startIndex = event.messageEditorRequestResponse().get().selectionOffsets().get().startIndexInclusive();
			int endIndex = event.messageEditorRequestResponse().get().selectionOffsets().get().endIndexExclusive();

			String selectedText;

			if (selectionContext == SelectionContext.REQUEST) {
				selectedText = requestResponse.request().toString().substring(startIndex, endIndex);
			} else {
				selectedText = requestResponse.response().toString().substring(startIndex, endIndex);
			}

			JMenuItem retrieveSelectedRequestItem = new JMenuItem(Strings.CONTEXT_MENU_STRING);
			retrieveSelectedRequestItem.addActionListener(e -> jstC.contextActionSendJWTtoSuiteTab(selectedText, true));

			menuItemList.add(retrieveSelectedRequestItem);
		}

		return menuItemList;
	}
}
