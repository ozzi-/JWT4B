package app.controllers;

import java.util.LinkedList;
import java.util.List;

import javax.swing.JMenuItem;

import app.helpers.Output;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import model.Strings;

import static org.apache.commons.lang.StringUtils.isNotEmpty;

// This controller handles the right-click context option "Send selected text to JWT4B Tab to decode
// which is available in the Raw view of the HTTP history tab

public class ContextMenuController implements IContextMenuFactory {
    private final JWTSuiteTabController jstC;

    public ContextMenuController(JWTSuiteTabController jstC) {
        this.jstC = jstC;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        String selectedText = selectedText(invocation);
        List<JMenuItem> menuItems = new LinkedList<>();

        if (isNotEmpty(selectedText)) {
            JMenuItem item = new JMenuItem(Strings.contextMenuString);
            item.addActionListener(e -> jstC.contextActionSendJWTtoSuiteTab(selectedText, true));

            menuItems.add(item);
        }

        return menuItems;
    }

    private static String selectedText(IContextMenuInvocation invocation) {
        int[] selection = invocation.getSelectionBounds();

        if (selection == null) { // only if user currently is in an input field
            return "";
        }

        IHttpRequestResponse ihrr = invocation.getSelectedMessages()[0];
        byte iContext = invocation.getInvocationContext();

        switch (iContext) {
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
                return new String(ihrr.getRequest()).substring(selection[0], selection[1]);

            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
                return new String(ihrr.getResponse()).substring(selection[0], selection[1]);

            default:
                Output.outputError("This context menu case (" + invocation + ") has not been covered yet!");
                return "";
        }
    }
}
