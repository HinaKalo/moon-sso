package cloud.moonl.sso.spring.core;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/** The {@code User-Agent} sent by the SDK: {@code moon-sso-sdk-java/<version>}. */
public final class MoonSsoUserAgent {

	/** SDK version as packaged. */
	public static final String VERSION = loadVersion();

	/** Full User-Agent header value. */
	public static final String VALUE = "moon-sso-sdk-java/" + VERSION;

	private MoonSsoUserAgent() {
	}

	private static String loadVersion() {
		try (InputStream in = MoonSsoUserAgent.class.getResourceAsStream("/META-INF/moon-sso-sdk.properties")) {
			if (in != null) {
				Properties p = new Properties();
				p.load(in);
				String v = p.getProperty("version");
				if (v != null && !v.isBlank() && !v.contains("${")) {
					return v.trim();
				}
			}
		}
		catch (IOException ex) {
			// fall through to the package version
		}
		String pkg = MoonSsoUserAgent.class.getPackage().getImplementationVersion();
		return (pkg != null) ? pkg : "dev";
	}

}
