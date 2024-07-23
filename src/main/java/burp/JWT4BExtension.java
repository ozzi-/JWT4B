package burp;

import app.controllers.HighLightController;
import app.controllers.JWTSuiteTabController;
import app.helpers.Config;
import app.helpers.Output;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.http.Http;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import gui.JWTSuiteTab;
import gui.RSyntaxTextAreaFactory;
import model.JWTSuiteTabModel;
import model.Settings;

public class JWT4BExtension implements BurpExtension {
	@Override
	public void initialize(MontoyaApi api) {
		Extension extension = api.extension();
		UserInterface userInterface = api.userInterface();
		Logging logging = api.logging();
		Http http = api.http();

		RSyntaxTextAreaFactory rSyntaxTextAreaFactory = new RSyntaxTextAreaFactory(userInterface);

		// Logging
		Output.initialise(logging);
		Output.output("JWT4B says hi!");

		// Editor
		JWT4BEditorProvider editorProvider = new JWT4BEditorProvider(rSyntaxTextAreaFactory,api);
		userInterface.registerHttpRequestEditorProvider(editorProvider);
		userInterface.registerHttpResponseEditorProvider(editorProvider);

		// Settings
		Config.loadConfig();

		// Request & Response Highlighter
		final HighLightController highLightController = new HighLightController();
		http.registerHttpHandler(highLightController);

		// SuiteTab
		JWTSuiteTabModel jwtSuiteTabModel = new JWTSuiteTabModel();
		JWTSuiteTab suiteTab = new JWTSuiteTab(jwtSuiteTabModel, rSyntaxTextAreaFactory,api);
		api.userInterface().registerSuiteTab(Settings.TAB_NAME, suiteTab);
		// Context Menu
		JWTSuiteTabController tabController = new JWTSuiteTabController(jwtSuiteTabModel, suiteTab);
		userInterface.registerContextMenuItemsProvider(new JWT4BContextMenuItemsProvider(tabController));

		extension.setName(Settings.EXTENSION_NAME);
	}
}
