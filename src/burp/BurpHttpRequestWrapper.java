package burp;

import oauth.signpost.http.HttpRequest;
import java.util.*;
import java.io.*;

public class BurpHttpRequestWrapper implements HttpRequest {

	private IHttpRequestResponse request;
	private IExtensionHelpers helpers;

	public BurpHttpRequestWrapper(IHttpRequestResponse request, IExtensionHelpers helpers) {
		this.request = request;
		this.helpers = helpers;
	}

	public IRequestInfo getRequestInfo() {
		return helpers.analyzeRequest(request);
	}

	public String getMethod() {
		return getRequestInfo().getMethod();
	}

	public String getRequestUrl() {
		return getRequestInfo().getUrl().toString();
	}

	public String getContentType() {
		return getHeader("Content-Type");
	}

	public String getHeader(String name) {
		return getAllHeaders().get(name);
	}

	public Map<String, String> getAllHeaders() {
		Map<String, String> retval = new HashMap<String, String>();
		for (String header : getRequestInfo().getHeaders()) {
			String[] parts = header.split(":", 2);
			retval.put(parts[0], parts[1]);
		}
		return retval;
	}

	public void setHeader(String name, String value) {
		byte state = 0; // 0 - first/wrong line, 1 - wait for \n, 2 - key, 3 - value, 4 - append, 5 - overwrite
		int namePos = 0, valueStart = 0, valueEnd = 0; // start - ':', end - '\r'
		final byte[] req = request.getRequest();
		for (int pos = 0; pos < req.length; pos++) {
			char b = (char)req[pos];
			switch (state) {
				case 0:
					if (b == '\r') state = 1;
					break;
				case 1:
					if (b == '\n') {
						state = 2;
						namePos = 0;
					}
					break;
				case 2:
					if (b == ':') {
						state = 3;
						valueStart = pos; 
					} else if (b == '\r' || b == '\n') {
						state = 4;
						valueStart = pos;
					} else if (name.charAt(namePos) != b) {
						state = 0;
					} else {
						namePos++;
					}
					break;
				case 3:
					if (b == '\r') {
						state = 5;
						valueEnd = pos;
					}
					break;
			}
			if (state > 3) break;
		}
		byte[] updated;
		if (state == 5) {
			byte[] toInsert = value.getBytes();
			updated = new byte[req.length - (valueEnd - valueStart - 2) + toInsert.length];
			System.arraycopy(req, 0, updated, 0, valueStart + 2);
			System.arraycopy(toInsert, 0, updated, valueStart + 2, toInsert.length);
			System.arraycopy(req, valueEnd, updated, valueStart + 2 + toInsert.length,
					req.length - valueEnd);
		} else {
			byte[] toInsert = String.format("%s: %s\r\n", name, value).getBytes();
			updated = new byte[req.length + toInsert.length];
			System.arraycopy(req, 0, updated, 0, valueStart);
			System.arraycopy(toInsert, 0, updated, valueStart, toInsert.length);
			System.arraycopy(req, valueStart, updated, valueStart + toInsert.length,
					req.length - valueStart);
		}
		request.setRequest(updated);
	}

	public InputStream getMessagePayload() throws IOException {
		return null;
	}

	public IHttpRequestResponse unwrap() {
		return request;
	}

	public void setRequestUrl(String url) {
		throw new RuntimeException("BurpHttpRequestWrapper.setRequestUrl is not implemented");
	}
}
