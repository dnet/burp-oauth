package burp;

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
		}
	}
}
