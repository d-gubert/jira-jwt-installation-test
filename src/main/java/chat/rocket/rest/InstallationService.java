package chat.rocket.rest;

import com.atlassian.annotations.security.XsrfProtectionExcluded;
import com.atlassian.jwt.CanonicalHttpRequest;
import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.core.http.JavaxJwtRequestExtractor;
import com.atlassian.jwt.core.http.JwtRequestExtractor;
import com.atlassian.jwt.core.reader.JwtClaimVerifiersBuilder;
import com.atlassian.jwt.core.reader.JwtIssuerSharedSecretService;
import com.atlassian.jwt.core.reader.JwtIssuerValidator;
import com.atlassian.jwt.core.reader.NimbusJwtReaderFactory;
import com.atlassian.jwt.exception.JwtIssuerLacksSharedSecretException;
import com.atlassian.jwt.exception.JwtParseException;
import com.atlassian.jwt.exception.JwtUnknownIssuerException;
import com.atlassian.jwt.exception.JwtVerificationException;
import com.atlassian.jwt.reader.JwtClaimVerifier;
import com.atlassian.jwt.reader.JwtReaderFactory;
import com.atlassian.plugins.rest.common.security.AnonymousAllowed;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

/**
 * A resource of message.
 */
@Path("/installation")
@Produces({MediaType.APPLICATION_JSON})
@AnonymousAllowed
public class InstallationService {

    private static JwtRequestExtractor<HttpServletRequest> jwtRequestExtractor = new JavaxJwtRequestExtractor();

    @POST
    @XsrfProtectionExcluded
    @Consumes(MediaType.APPLICATION_JSON)
    public Response postInstall(@Context HttpServletRequest request) throws JwtVerificationException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException, JwtParseException, UnsupportedEncodingException, NoSuchAlgorithmException
    {
        System.out.println(request.getHeader("Authorization"));

        JwtIssuerValidator issuerValidator = s -> true;
        JwtIssuerSharedSecretService issuerSharedSecretService = s -> s;

        JwtReaderFactory jwtReaderFactory = new NimbusJwtReaderFactory(issuerValidator, issuerSharedSecretService);

        CanonicalHttpRequest canonicalHttpRequest = jwtRequestExtractor.getCanonicalHttpRequest(request);

        System.out.println("CanonicalHttpRequest");

        Map<String, ? extends JwtClaimVerifier> requiredClaims = JwtClaimVerifiersBuilder.build(canonicalHttpRequest);

        String jwt = jwtRequestExtractor.extractJwt(request);

        System.out.println("JWT = " + jwt);

        Jwt validatedJwt = jwtReaderFactory.getReader(jwt).readAndVerify(jwt, requiredClaims);

        System.out.println(validatedJwt);

        return Response.ok().build();
    }
}
