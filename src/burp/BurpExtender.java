package burp;

import app.controllers.ContextMenuController;
import app.controllers.HighLightController;
import app.controllers.JWTInterceptTabController;
import app.controllers.JWTSuiteTabController;
import app.controllers.JWTTabController;
import app.helpers.Config;
import app.helpers.Output;
import gui.JWTInterceptTab;
import gui.JWTSuiteTab;
import gui.JWTViewTab;
import gui.RSyntaxTextAreaFactory;
import model.JWTInterceptModel;
import model.JWTSuiteTabModel;
import model.JWTTabModel;
import model.Settings;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {

  private IBurpExtenderCallbacks callbacks;
  private RSyntaxTextAreaFactory rSyntaxTextAreaFactory;

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;

    Output.initialise(callbacks.getStdout(), callbacks.getStderr());
    Output.output("JWT4B says hi!");
    rSyntaxTextAreaFactory = new RSyntaxTextAreaFactory(callbacks);


    callbacks.setExtensionName(Settings.EXTENSION_NAME);
    callbacks.registerMessageEditorTabFactory(this);

    Config.loadConfig();

    final HighLightController marker = new HighLightController(callbacks);
    callbacks.registerHttpListener(marker);

    // Suite Tab
    JWTSuiteTabModel jwtSTM = new JWTSuiteTabModel();
    JWTSuiteTab jwtST = new JWTSuiteTab(jwtSTM, rSyntaxTextAreaFactory);
    JWTSuiteTabController jstC = new JWTSuiteTabController(jwtSTM, jwtST);
    callbacks.addSuiteTab(jstC);

    // Context Menu
    ContextMenuController cmC = new ContextMenuController(jstC);
    callbacks.registerContextMenuFactory(cmC);
  }

  @Override
  public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
    IMessageEditorTab jwtTC;
    if (editable) { // Intercept
      JWTInterceptModel jwtSTM = new JWTInterceptModel();
      JWTInterceptTab jwtST = new JWTInterceptTab(jwtSTM, rSyntaxTextAreaFactory);
      jwtTC = new JWTInterceptTabController(callbacks, jwtSTM, jwtST);
    } else {
      JWTTabModel jwtTM = new JWTTabModel();
      JWTViewTab jwtVT = new JWTViewTab(jwtTM, rSyntaxTextAreaFactory);
      jwtTC = new JWTTabController(callbacks, jwtTM, jwtVT);
    }
    return jwtTC;
  }

  public IBurpExtenderCallbacks getCallbacks() {
    return callbacks;
  }
}
