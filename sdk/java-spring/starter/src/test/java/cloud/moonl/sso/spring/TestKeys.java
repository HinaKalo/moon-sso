package cloud.moonl.sso.spring;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/** Locally generated signing keys and helpers to mint test JWTs. */
public final class TestKeys {

	public final RSAKey rsa;

	public final ECKey ec;

	public TestKeys() {
		try {
			this.rsa = new RSAKeyGenerator(2048).keyID("rsa-test").generate();
			this.ec = new ECKeyGenerator(Curve.P_256).keyID("ec-test").generate();
		}
		catch (JOSEException ex) {
			throw new IllegalStateException(ex);
		}
	}

	public JWKSource<SecurityContext> jwkSource() {
		return new ImmutableJWKSet<>(new JWKSet(List.of(this.rsa.toPublicJWK(), this.ec.toPublicJWK())));
	}

	public String signRs256(String typ, JWTClaimsSet claims) {
		return sign(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(this.rsa.getKeyID())
			.type((typ != null) ? new JOSEObjectType(typ) : null)
			.build(), claims, true);
	}

	public String signEs256(String typ, JWTClaimsSet claims) {
		return sign(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(this.ec.getKeyID())
			.type((typ != null) ? new JOSEObjectType(typ) : null)
			.build(), claims, false);
	}

	private String sign(JWSHeader header, JWTClaimsSet claims, boolean rsaKey) {
		try {
			SignedJWT jwt = new SignedJWT(header, claims);
			jwt.sign(rsaKey ? new RSASSASigner(this.rsa) : new ECDSASigner(this.ec));
			return jwt.serialize();
		}
		catch (JOSEException ex) {
			throw new IllegalStateException(ex);
		}
	}

	/** Claims of a valid back-channel logout token; {@code customizer} may change them. */
	public static JWTClaimsSet logoutClaims(String issuer, String clientId, Consumer<JWTClaimsSet.Builder> customizer) {
		Instant now = Instant.now();
		JWTClaimsSet.Builder b = new JWTClaimsSet.Builder().issuer(issuer)
			.audience(clientId)
			.issueTime(Date.from(now))
			.expirationTime(Date.from(now.plusSeconds(120)))
			.jwtID("jti-" + System.nanoTime())
			.subject("user-sub")
			.claim("sid", "sid-1")
			.claim("events", Map.of("http://schemas.openid.net/event/backchannel-logout", Map.of()));
		customizer.accept(b);
		return b.build();
	}

}
