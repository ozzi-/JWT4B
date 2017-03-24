package burp;

import app.controllers.ContextMenuController;
import app.controllers.JWTMessageEditorTabController;
import app.controllers.JWTSuiteTabController;
import app.helpers.Settings;
import gui.JWTEditableTab;
import gui.JWTSuiteTab;
import gui.JWTViewTab;
import model.JWTSuiteTabModel;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
	private IBurpExtenderCallbacks callbacks;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName(Settings.extensionName);
		callbacks.registerMessageEditorTabFactory(this);
		// Suite Tab
		JWTSuiteTabModel jwtSTM =  new JWTSuiteTabModel();
		JWTSuiteTab jwtST = new JWTSuiteTab(jwtSTM);
		JWTSuiteTabController jstC = new JWTSuiteTabController(jwtSTM, jwtST);
		callbacks.addSuiteTab(jstC);
		// Context Menu
		ContextMenuController cmC = new ContextMenuController(jstC);
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
