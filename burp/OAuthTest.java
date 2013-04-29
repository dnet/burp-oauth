package burp;

import java.io.*;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.Ignore;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import oauth.signpost.http.HttpRequest;

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

	@Ignore
	public static HttpRequest reqWrapForTestInput(int num) throws IOException {
		RandomAccessFile f = new RandomAccessFile(String.format("test-inputs/%d.txt", num), "r");
		final byte[] req = new byte[(int)f.length()];
		f.read(req);
		IHttpRequestResponse request = new MockRequest(req);
		return new BurpHttpRequestWrapper(request);
	}

	private static class MockRequest implements IHttpRequestResponse {
		private byte[] request;

		public MockRequest(byte[] request) {
			this.request = request;
		}

		public String getComment()           { return null; }
		public String getHighlight()         { return null; }
		public IHttpService getHttpService() { return null; }
		public byte[] getRequest()           { return request; }
		public byte[] getResponse()          { return null; }
		public void setComment(String comment) {}
		public void setHighlight(String color) {}
		public void setHttpService(IHttpService httpService) {}
		public void setRequest(byte[] message) { this.request = message; }
		public void setResponse(byte[] message) {}
	}
}
