package burp;

import java.io.*;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.Ignore;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import oauth.signpost.basic.DefaultOAuthConsumer;
import oauth.signpost.http.HttpRequest;
import oauth.signpost.OAuthConsumer;

@RunWith(JUnit4.class)
public class OAuthTest {
	@Test
	public void testGetMethod() throws IOException {
		HttpRequest hr;
		hr = reqWrapForTestInput(1);
		assertEquals(hr.getMethod(), "GET");
		hr = reqWrapForTestInput(2);
		assertEquals(hr.getMethod(), "POST");
	}

	@Test
	public void testGetContentType() throws IOException {
		HttpRequest hr;
		hr = reqWrapForTestInput(1);
		assertEquals(hr.getContentType(), null);
		hr = reqWrapForTestInput(2);
		assertEquals(hr.getContentType(), "text/xml; charset=utf-8");
	}

	@Test
	public void testGetHeader() throws IOException {
		HttpRequest hr;
		hr = reqWrapForTestInput(1);
		assertEquals(hr.getHeader("Accept"), "application/json");
		assertEquals(hr.getHeader("Host"), "silentsignal.hu");
		assertEquals(hr.getHeader("Connection"), "Keep-Alive");
		assertEquals(hr.getHeader("User-Agent"), "Silent Signal");
		assertEquals(hr.getHeader("Non-Existent"), null);
		hr = reqWrapForTestInput(2);
		assertEquals(hr.getHeader("Host"), "weirdport.foo.bar:8081");
	}

	private final static String INSERT_HEADER_NAME = "Inserted";
	private final static String INSERT_HEADER_VALUE = "foo bar";

	@Test
	public void testInsertHeader() throws IOException {
		HttpRequest hr = reqWrapForTestInput(1);
		assertEquals(hr.getHeader(INSERT_HEADER_NAME), null);
		hr.setHeader(INSERT_HEADER_NAME, INSERT_HEADER_VALUE);
		assertEquals(hr.getHeader(INSERT_HEADER_NAME), INSERT_HEADER_VALUE);
	}

	private final static String UPDATE_HEADER_NAME = "Host";
	private final static String UPDATE_HEADER_OLD = "silentsignal.hu";
	private final static String UPDATE_HEADER_VALUE = "silentsignal.eu";

	@Test
	public void testUpdateHeader() throws IOException {
		HttpRequest hr = reqWrapForTestInput(1);
		assertEquals(hr.getHeader(UPDATE_HEADER_NAME), UPDATE_HEADER_OLD);
		hr.setHeader(UPDATE_HEADER_NAME, UPDATE_HEADER_VALUE);
		assertEquals(hr.getHeader(UPDATE_HEADER_NAME), UPDATE_HEADER_VALUE);
		assertEquals(hr.getHeader("Connection"), "Keep-Alive"); // next one
	}

	@Test
	public void testGetRequestUrl() throws IOException {
		HttpRequest hr = reqWrapForTestInput(1);
		assertEquals(hr.getRequestUrl(), "http://silentsignal.hu:1337/foo/bar");
	}

	@Test
	public void testSignature() throws Exception {
		HttpRequest hr = reqWrapForTestInput(1);
		OAuthConsumer consumer = new DefaultOAuthConsumer("1234", "5678");
		consumer.setTokenWithSecret("9ABC", "DEF0");
		consumer.sign(hr);
	}

	@Ignore
	public static HttpRequest reqWrapForTestInput(int num) throws IOException {
		RandomAccessFile f = new RandomAccessFile(String.format("test-inputs/%d.txt", num), "r");
		final byte[] req = new byte[(int)f.length()];
		f.read(req);
		IHttpRequestResponse request = new MockRequest(req);
		HttpRequest reqWrap = new BurpHttpRequestWrapper(request, null);
		request.setHttpService(new MockService(reqWrap.getHeader("Host")));
		return reqWrap;
	}

	private static class MockRequest implements IHttpRequestResponse {
		private byte[] request;
		private IHttpService httpService = null;

		public MockRequest(byte[] request) {
			this.request = request;
		}

		public String getComment()           { return null; }
		public String getHighlight()         { return null; }
		public IHttpService getHttpService() { return httpService; }
		public byte[] getRequest()           { return request; }
		public byte[] getResponse()          { return null; }
		public void setComment(String comment) {}
		public void setHighlight(String color) {}
		public void setHttpService(IHttpService httpService) { this.httpService = httpService; }
		public void setRequest(byte[] message) { this.request = message; }
		public void setResponse(byte[] message) {}
	}

	private static class MockService implements IHttpService {
		private final String host;

		public MockService(String host) {
			this.host = host;
		}

		public String getHost() { return host; }
		public int getPort() { return 1337; }
		public String getProtocol() { return "http"; }
	}
}
