package burp;

public class OAuthConfig {
	public static final boolean scopeOnly = false; // true ignores out of scope requests

	public static String getConsumerKey() {
		return "ConsumerKey";
	}

	public static String getConsumerSecret() {
		return "ConsumerSecret";
	}

	public static String getToken() {
		return "Token";
	}

	public static String getTokenSecret() {
		return "TokenSecret";
	}
}
