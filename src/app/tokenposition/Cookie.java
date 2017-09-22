package app.tokenposition;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;

import app.helpers.ConsoleOut;
import app.helpers.PostParameter;

public class Cookie extends ITokenPosition {

	@Override
	public boolean positionFound() {
		return false;
	}

	@Override
	public String getToken() {
		return null;
	}

	@Override
	public byte[] replaceToken(String newToken) {
		return null;
	}
}
