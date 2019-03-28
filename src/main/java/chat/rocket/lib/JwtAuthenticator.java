package chat.rocket.lib;

import com.atlassian.jwt.Jwt;
import com.atlassian.jwt.core.http.JwtRequestExtractor;
import com.atlassian.jwt.core.http.auth.AbstractJwtAuthenticator;
import com.atlassian.jwt.core.http.auth.AuthenticationResultHandler;
import com.atlassian.jwt.exception.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class JwtAuthenticator extends AbstractJwtAuthenticator {
    public JwtAuthenticator(JwtRequestExtractor jwtExtractor, AuthenticationResultHandler authenticationResultHandler)
    {
        super(jwtExtractor, authenticationResultHandler);
    }

    @Override
    protected Jwt verifyJwt(String s, Map map) throws JwtParseException, JwtVerificationException, JwtIssuerLacksSharedSecretException, JwtUnknownIssuerException, IOException, NoSuchAlgorithmException
    {
        return null;
    }

    @Override
    protected void tagRequest(Object o, Jwt jwt) throws JwtUserRejectedException
    {

    }
}
