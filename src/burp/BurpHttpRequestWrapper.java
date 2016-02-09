package burp;

import oauth.signpost.http.HttpRequest;
import java.nio.charset.Charset;
import java.util.*;
import java.io.*;

public class BurpHttpRequestWrapper implements HttpRequest {

	private IHttpRequestResponse request;
	private static final Charset UTF_8 = Charset.forName("UTF-8");

	public BurpHttpRequestWrapper(IHttpRequestResponse request) {
		this.request = request;
	}

	public String getMethod() {
		StringBuilder method = new StringBuilder();
		for (byte b : request.getRequest()) {
			if (b == ' ') {
				break;
			} else {
				method.append((char)b);
			}
		}
		return method.toString();
	}

	public String getRequestUrl() {
		IHttpService hs = request.getHttpService();
		StringBuilder url = new StringBuilder();
		url.append(hs.getProtocol());
		url.append("://");
		url.append(hs.getHost());
		url.append(":");
		url.append(hs.getPort());
		boolean capture = false;
		for (byte b : request.getRequest()) {
			if (b == ' ') {
				if (capture) {
					break;
				} else {
					capture = true;
				}
			} else if (capture) {
				url.append((char)b);
			}
		}
		return url.toString();
	}

	public String getContentType() {
		return getHeader("Content-Type");
	}

	public String getHeader(String name) {
		return getAllHeaders().get(name);
	}

	public Map<String, String> getAllHeaders() {
		Map<String, String> retval = new HashMap<String, String>();
		byte state = 0; // 0 - first line, 1 - wait for \n, 2 - key, 3 - value
		StringBuilder key = null, value = null;
		byteloop:
		for (byte b : request.getRequest()) {
			switch (state) {
				case 0:
					if (b == '\r') state = 1;
					break;
				case 1:
					if (b == '\n') {
						state = 2;
						key = new StringBuilder();
					}
					break;
				case 2:
					if (b == ':') {
						state = 3;
						value = new StringBuilder();
					} else if (b == '\r' || b == '\n') {
						break byteloop;
					} else {
						key.append((char)b);
					}
					break;
				case 3:
					if (b == '\r') {
						state = 1;
						retval.put(key.toString(), value.substring(1)); // starts with a space
					} else {
						value.append((char)b);
					}
					break;
			}
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
			byte[] toInsert = value.getBytes(UTF_8);
			updated = new byte[req.length - (valueEnd - valueStart - 2) + toInsert.length];
			System.arraycopy(req, 0, updated, 0, valueStart + 2);
			System.arraycopy(toInsert, 0, updated, valueStart + 2, toInsert.length);
			System.arraycopy(req, valueEnd, updated, valueStart + 2 + toInsert.length,
					req.length - valueEnd);
		} else {
			byte[] toInsert = String.format("%s: %s\r\n", name, value).getBytes(UTF_8);
			updated = new byte[req.length + toInsert.length];
			System.arraycopy(req, 0, updated, 0, valueStart);
			System.arraycopy(toInsert, 0, updated, valueStart, toInsert.length);
			System.arraycopy(req, valueStart, updated, valueStart + toInsert.length,
					req.length - valueStart);
		}
		request.setRequest(updated);
	}

	public InputStream getMessagePayload() throws IOException {
		final byte[] buf = request.getRequest();
		int newlines = 0;
		for (int offset = 0; offset < buf.length; offset++) {
			switch (newlines) {
				case 0:
				case 2:
					newlines = (buf[offset] == (byte)0x0d) ? newlines + 1 : 0;
					break;
				case 3:
					if (buf[offset] == (byte)0x0a) {
						offset++;
						return new ByteArrayInputStream(buf, offset, buf.length - offset);
					}
				case 1:
					newlines = (buf[offset] == (byte)0x0a) ? newlines + 1 : 0;
					break;
			}
		}
		return null;
	}

	public IHttpRequestResponse unwrap() {
		return request;
	}

	public void setRequestUrl(String url) {
		throw new RuntimeException("BurpHttpRequestWrapper.setRequestUrl is not implemented");
	}
}
