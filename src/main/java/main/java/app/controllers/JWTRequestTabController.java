package app.controllers;

import gui.JWTViewTab;
import model.JWTTabModel;

public class JWTRequestTabController extends JWTTabController {

    public JWTRequestTabController(JWTTabModel jwtTM, JWTViewTab jwtVT) {
        super(jwtTM, jwtVT, true);
    }

}
