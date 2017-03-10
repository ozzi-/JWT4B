package burp;

import app.Settings;
import app.controllers.ContextMenuController;
import app.controllers.JWTMessageEditorTabController;
import app.controllers.JWTSuiteTabController;
import gui.JWTEditableTab;
import gui.JWTViewTab;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
	private IBurpExtenderCallbacks callbacks;
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName(Settings.extensionName);
		callbacks.registerMessageEditorTabFactory(this);
		JWTSuiteTabController jstC = new JWTSuiteTabController();
		callbacks.addSuiteTab(jstC);
		ContextMenuController cmC = new ContextMenuController();
		callbacks.registerContextMenuFactory(cmC);
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		JWTMessageEditorTabController visualizer = new JWTMessageEditorTabController(callbacks);
		if (editable) {
			visualizer.addTab(new JWTEditableTab(visualizer));
		} else {
			visualizer.addTab(new JWTViewTab(visualizer));
		}
		return visualizer;
	}
	
	public IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}
}
