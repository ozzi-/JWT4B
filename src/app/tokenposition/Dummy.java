package app.tokenposition;

public class Dummy extends ITokenPosition {

	@Override
	public boolean positionFound() {
		return false;
	}

	@Override
	public String getToken() {
		return "eyJhbGciOiJIUzI1NiJ9.e30.4E_Bsx-pJi3kOW9wVXN8CgbATwP09D9V5gxh9-9zSZ0";
	}

	@Override
	public byte[] replaceToken(String newToken) {
		return "eyJhbGciOiJIUzI1NiJ9.e30.4E_Bsx-pJi3kOW9wVXN8CgbATwP09D9V5gxh9-9zSZ0".getBytes();
	}
}
