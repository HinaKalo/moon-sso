package cloud.moonl.sso.spring;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/** Minimal scripted HTTP server for unit tests (JDK built-in, loopback only). */
public final class StubServer implements AutoCloseable {

	/** A recorded request. */
	public record Recorded(String method, String path, String query, Map<String, List<String>> headers, String body) {
	}

	/** A canned response. */
	public record Reply(int status, String contentType, String body) {

		public static Reply json(int status, String body) {
			return new Reply(status, "application/json", body);
		}

	}

	/** Produces the response of a route. */
	@FunctionalInterface
	public interface Handler {

		Reply handle(Recorded request) throws IOException;

	}

	private final HttpServer server;

	private final Map<String, Handler> routes = new ConcurrentHashMap<>();

	public final List<Recorded> requests = new CopyOnWriteArrayList<>();

	public StubServer() throws IOException {
		this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
		this.server.createContext("/", this::dispatch);
		this.server.start();
	}

	public String baseUrl() {
		return "http://127.0.0.1:" + this.server.getAddress().getPort();
	}

	public StubServer route(String methodAndPath, Handler handler) {
		this.routes.put(methodAndPath, handler);
		return this;
	}

	public long count(String path) {
		return this.requests.stream().filter((r) -> r.path().equals(path)).count();
	}

	private void dispatch(HttpExchange exchange) throws IOException {
		String body;
		try (InputStream in = exchange.getRequestBody()) {
			body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
		}
		Recorded recorded = new Recorded(exchange.getRequestMethod(), exchange.getRequestURI().getPath(),
				exchange.getRequestURI().getRawQuery(), Map.copyOf(exchange.getRequestHeaders()), body);
		this.requests.add(recorded);
		Handler handler = this.routes.get(recorded.method() + " " + recorded.path());
		Reply reply = (handler != null) ? handler.handle(recorded) : Reply.json(404, "{\"error\":\"not_found\"}");
		byte[] bytes = reply.body().getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", reply.contentType());
		exchange.sendResponseHeaders(reply.status(), bytes.length == 0 ? -1 : bytes.length);
		if (bytes.length > 0) {
			try (OutputStream out = exchange.getResponseBody()) {
				out.write(bytes);
			}
		}
		exchange.close();
	}

	@Override
	public void close() {
		this.server.stop(0);
	}

}
