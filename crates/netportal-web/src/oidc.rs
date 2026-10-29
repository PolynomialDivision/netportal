//! The login with Authentik (OpenID Connect, INVENTORY 4.4) through the `openidconnect` crate:
//! discovery of `<NETPORTAL_OIDC_ISSUER>/.well-known/openid-configuration` (lazily at the first
//! login, cached for an hour, dropped after a failed ID token check so a rotated signing key is
//! fetched again), the authorization code flow with PKCE S256, `state` and `nonce` (kept in the
//! encrypted session cookie), the code exchange with the client secret (HTTP Basic), and the
//! ID token's validation (signature against the provider's JWKS, `iss`, `aud`, `exp`, `nonce`).
//! The claims come from the validated ID token only: `sub` (required: a token without it is a
//! failed login), `preferred_username`, `name` and Authentik's `groups` (names).
//!
//! The HTTP client is the workspace's reqwest: no redirects (SSRF), 10 s per request, answers
//! read up to 1 MiB. A plain-http issuer is accepted only on a loopback address (tests).

use std::sync::Arc;
use std::time::{Duration, Instant};

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreRevocableToken,
    CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, AuthenticationFlow, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
    EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpRequest, HttpResponse, IdTokenFields,
    IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RequestTokenError, Scope,
    StandardErrorResponse, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

const LOG: &str = "netportal.oidc";
/// The provider's metadata and keys are read again after this long.
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ANSWER: usize = 1 << 20;

/// Authentik's `groups` claim (group names) next to the standard claims.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct HouseClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
}

impl AdditionalClaims for HouseClaims {}

type IdFields = IdTokenFields<
    HouseClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;
type TokenResponse = StandardTokenResponse<IdFields, CoreTokenType>;
type HouseClient = Client<
    HouseClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    TokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// What the login learns from a validated ID token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub sub: String,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    /// `None`: no `groups` claim
    pub groups: Option<Vec<String>>,
}

/// A login that failed; the text is a kind for the log (never a code, token or answer body).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct LoginFailed(pub String);

/// The HTTP client's error (its text names the kind, not the URL).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct HttpError(String);

/// A started login: where to send the browser, and what the callback needs back.
pub struct Started {
    pub url: url::Url,
    pub state: String,
    pub nonce: String,
    pub verifier: String,
}

/// The portal's OIDC client (one per process).
pub struct Oidc {
    issuer: IssuerUrl,
    client_id: String,
    client_secret: String,
    redirect: RedirectUrl,
    http: reqwest::Client,
    cached: Mutex<Option<(Instant, Arc<HouseClient>)>>,
}

impl Oidc {
    /// `issuer` as configured (Authentik's ends with a slash), the callback URL
    /// (`NETPORTAL_BASE_URL` + `/auth/callback`).
    pub fn new(issuer: &str, client_id: &str, client_secret: &str, redirect: &str) -> Result<Oidc, String> {
        let parsed = url::Url::parse(issuer).map_err(|e| format!("NETPORTAL_OIDC_ISSUER: {e}"))?;
        let loopback = match parsed.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(d)) => d == "localhost",
            None => false,
        };
        match parsed.scheme() {
            "https" => {}
            "http" if loopback => {}
            _ => return Err("NETPORTAL_OIDC_ISSUER: must be https (plain http only on a loopback address)".into()),
        }
        let issuer = IssuerUrl::new(issuer.to_string()).map_err(|e| format!("NETPORTAL_OIDC_ISSUER: {e}"))?;
        let redirect = RedirectUrl::new(redirect.to_string()).map_err(|e| format!("NETPORTAL_BASE_URL: {e}"))?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| format!("HTTP client: {e}"))?;
        Ok(Oidc {
            issuer,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            redirect,
            http,
            cached: Mutex::new(None),
        })
    }

    async fn client(&self) -> Result<Arc<HouseClient>, LoginFailed> {
        let mut cached = self.cached.lock().await;
        if let Some((at, client)) = cached.as_ref()
            && at.elapsed() < DISCOVERY_TTL
        {
            return Ok(client.clone());
        }
        let http = |req: HttpRequest| send(self.http.clone(), req);
        let metadata = CoreProviderMetadata::discover_async(self.issuer.clone(), &http).await.map_err(|e| {
            tracing::warn!(target: LOG, "discovery failed: {e}");
            LoginFailed("discovery failed".into())
        })?;
        let client: HouseClient = Client::from_provider_metadata(
            metadata,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(self.redirect.clone());
        let client = Arc::new(client);
        *cached = Some((Instant::now(), client.clone()));
        Ok(client)
    }

    async fn forget(&self) {
        *self.cached.lock().await = None;
    }

    /// The authorization request: response_type code, scope `openid profile email`, state,
    /// nonce, PKCE S256.
    pub async fn start(&self) -> Result<Started, LoginFailed> {
        let client = self.client().await?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = client
            .authorize_url(
                AuthenticationFlow::<openidconnect::core::CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("profile".into()))
            .add_scope(Scope::new("email".into()))
            .set_pkce_challenge(challenge)
            .url();
        Ok(Started {
            url,
            state: state.secret().clone(),
            nonce: nonce.secret().clone(),
            verifier: verifier.secret().clone(),
        })
    }

    /// The callback: exchange the code (with the PKCE verifier) and validate the ID token (with
    /// the nonce); its claims.
    pub async fn finish(&self, code: &str, verifier: &str, nonce: &str) -> Result<Claims, LoginFailed> {
        let client = self.client().await?;
        let http = |req: HttpRequest| send(self.http.clone(), req);
        let request = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|_| LoginFailed("no token endpoint".into()))?
            .set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()));
        let response = request.request_async(&http).await.map_err(|e| {
            LoginFailed(match e {
                RequestTokenError::ServerResponse(r) => format!("token endpoint: {}", r.error().as_ref()),
                RequestTokenError::Request(e) => format!("token endpoint: {e}"),
                RequestTokenError::Parse(..) => "token endpoint: unreadable answer".into(),
                RequestTokenError::Other(_) => "token endpoint: unexpected answer".into(),
            })
        })?;
        let Some(id_token) = response.extra_fields().id_token() else {
            return Err(LoginFailed("no ID token".into()));
        };
        let verified = id_token.claims(&client.id_token_verifier(), &Nonce::new(nonce.to_string()));
        let claims = match verified {
            Ok(claims) => claims,
            Err(e) => {
                self.forget().await;
                return Err(LoginFailed(format!("ID token: {}", verification_kind(&e))));
            }
        };
        let sub = claims.subject().as_str().to_string();
        if sub.is_empty() {
            return Err(LoginFailed("ID token: empty sub".into()));
        }
        Ok(Claims {
            sub,
            preferred_username: claims.preferred_username().map(|u| u.as_str().to_string()).filter(|u| !u.is_empty()),
            name: claims.name().and_then(|n| n.get(None)).map(|n| n.as_str().to_string()).filter(|n| !n.is_empty()),
            groups: claims.additional_claims().groups.clone(),
        })
    }
}

fn verification_kind(e: &openidconnect::ClaimsVerificationError) -> &'static str {
    use openidconnect::ClaimsVerificationError as E;
    match e {
        E::Expired(_) => "expired",
        E::InvalidAudience(_) => "audience",
        E::InvalidAuthContext(_) | E::InvalidAuthTime(_) => "auth context",
        E::InvalidIssuer(_) => "issuer",
        E::InvalidNonce(_) => "nonce",
        E::InvalidSubject(_) => "subject",
        E::SignatureVerification(_) => "signature",
        E::Unsupported(_) => "unsupported",
        _ => "invalid claims",
    }
}

/// One request of the OIDC client through reqwest (no redirects, bounded answer).
async fn send(http: reqwest::Client, req: HttpRequest) -> Result<HttpResponse, HttpError> {
    let request = reqwest::Request::try_from(req).map_err(|_| HttpError("bad request".into()))?;
    let mut response = http.execute(request).await.map_err(|e| {
        HttpError(if e.is_timeout() {
            "timeout".into()
        } else if e.is_connect() {
            "connection failed".into()
        } else {
            "request failed".into()
        })
    })?;
    let mut builder = http::Response::builder().status(response.status());
    for (name, value) in response.headers() {
        builder = builder.header(name, value);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| HttpError("answer not readable".into()))? {
        if body.len() + chunk.len() > MAX_ANSWER {
            return Err(HttpError("answer too large".into()));
        }
        body.extend_from_slice(&chunk);
    }
    builder.body(body).map_err(|_| HttpError("answer not readable".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuer_must_be_https_unless_loopback() {
        let ok = |issuer: &str| Oidc::new(issuer, "c", "s", "https://wifi.example/auth/callback").is_ok();
        assert!(ok("https://login.example.org/application/o/netportal/"));
        assert!(ok("http://127.0.0.1:29000/application/o/netportal/"));
        assert!(ok("http://[::1]:29000/application/o/netportal/"));
        assert!(!ok("http://login.example.org/application/o/netportal/"));
        assert!(!ok("ftp://login.example.org/"));
        assert!(!ok("not a url"));
    }
}
