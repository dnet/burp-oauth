package burp;

import oauth.signpost.basic.DefaultOAuthConsumer;
import oauth.signpost.http.HttpRequest;
import oauth.signpost.OAuthConsumer;
import oauth.signpost.exception.OAuthException;

public class BurpExtender implements IBurpExtender, IHttpListener
{
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		callbacks.setExtensionName("OAuth");
		callbacks.registerHttpListener(this);
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	{
		if (messageIsRequest)
		{
			HttpRequest req = new BurpHttpRequestWrapper(messageInfo);
			OAuthConsumer consumer = new DefaultOAuthConsumer(
					OAuthConfig.getConsumerKey(),
					OAuthConfig.getConsumerSecret());
			consumer.setTokenWithSecret(OAuthConfig.getToken(),
					OAuthConfig.getTokenSecret());
			try {
				consumer.sign(req);
			} catch (OAuthException oae) {
				oae.printStackTrace();
			}
		}
	}
}
