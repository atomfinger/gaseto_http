//// Send, read and check PASETO tokens over HTTP, with
//// [Gaseto](https://hexdocs.pm/gaseto/). It works with any server built on
//// [gleam_http](https://hexdocs.pm/gleam_http/), such as Wisp and Mist.
////
//// Once a user has logged in, hand them a token with `access_token_response`
//// ([RFC 6749, section 5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1)):
////
//// ```gleam
//// let lifetime = duration.minutes(15)
//// let claims =
////   gaseto.new_claims()
////   |> gaseto.with_issuer("login.example.com")
////   |> gaseto.with_audience("api.example.com")
////   |> gaseto.with_subject(user_identifier)
////   |> gaseto.expires_in(lifetime)
//// let assert Ok(token) = gaseto.sign(claims, secret_key)
//// gaseto_http.access_token_response(token, lifetime)
//// // -> 200 OK, with the token in a JSON body:
//// // {"access_token":"v4.public.eyJ...","token_type":"Bearer","expires_in":900}
//// ```
////
//// The client sends it back on later requests as a bearer token
//// ([RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)),
//// `Authorization: Bearer <token>`. Check it with `require_verified_bearer`,
//// so the rest of the handler only runs for a valid token:
////
//// ```gleam
//// let rules =
////   gaseto.new_rules()
////   |> gaseto.issued_by("login.example.com")
////   |> gaseto.for_audience("api.example.com")
//// use _token <- gaseto_http.require_verified_bearer(
////   request,
////   key: public_key,
////   rules:,
////   realm: "api.example.com",
////   error_body: "",
//// )
//// response.new(200) |> response.set_body("Hello, user")
//// ```
////
//// To read the token, for example its subject, use `verify_bearer`, or keep
//// the token `require_verified_bearer` passes on.
////
//// For a browser, the token can live in a cookie instead: see
//// `set_token_cookie` and `require_verified_cookie`.

import gaseto
import gaseto/error.{type TokenValidationError}
import gleam/http/cookie
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/list
import gleam/option.{Some}
import gleam/result
import gleam/string
import gleam/time/duration.{type Duration}

/// Why a bearer token could not be used.
pub type BearerError {
  /// The request has no `Authorization` header with the `Bearer` scheme. A
  /// request that uses another scheme, such as `Basic`, counts as having no
  /// token.
  MissingToken
  /// The `Authorization` header uses the `Bearer` scheme, but does not hold
  /// one token in the form RFC 6750 requires
  /// ([RFC 6750, section 2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1)),
  /// or the request has more than one `Authorization` header
  /// ([RFC 9110, section 5.3](https://www.rfc-editor.org/rfc/rfc9110#section-5.3)).
  MalformedAuthorization
  /// Gaseto refused the token.
  InvalidToken(error: TokenValidationError)
}

/// Why a token cookie could not be used.
pub type CookieError {
  /// The request has no cookie with the given name, or it is empty, as after
  /// `expire_token_cookie`.
  MissingCookie
  /// The request has more than one cookie with the given name. A page on
  /// another subdomain can add a second one, so neither is trusted. A name
  /// starting with `__Host-` prevents this
  /// ([OWASP, Cookie Name Prefixes](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookie-name-prefixes)).
  RepeatedCookie
  /// Gaseto refused the token.
  InvalidCookieToken(error: TokenValidationError)
}

/// The token from an `Authorization: Bearer <token>` header
/// ([RFC 6750, section 2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1)).
/// The scheme name is not case sensitive.
///
/// Most code wants `verify_bearer` or `decrypt_bearer` instead, which also
/// check the token.
pub fn bearer_token(request: Request(body)) -> Result(String, BearerError) {
  case list.key_filter(request.headers, "authorization") {
    [] -> Error(MissingToken)
    [authorization] -> read_bearer(string.trim(authorization))
    // Authorization is not a list field, so it may only be sent once
    _ -> Error(MalformedAuthorization)
  }
}

/// Reads the bearer token and verifies it as a `public` token. See
/// `gaseto.verify`.
pub fn verify_bearer(
  request: Request(body),
  key key: gaseto.PublicKey,
  rules rules: gaseto.Rules,
) -> Result(gaseto.Token, BearerError) {
  use token <- result.try(bearer_token(request))
  gaseto.verify(token, key, rules) |> result.map_error(InvalidToken)
}

/// Reads the bearer token and decrypts it as a `local` token. See
/// `gaseto.decrypt`.
pub fn decrypt_bearer(
  request: Request(body),
  key key: gaseto.LocalKey,
  rules rules: gaseto.Rules,
) -> Result(gaseto.Token, BearerError) {
  use token <- result.try(bearer_token(request))
  gaseto.decrypt(token, key, rules) |> result.map_error(InvalidToken)
}

/// Runs `next` with the token when the bearer token verifies, and answers
/// with `error_response` otherwise. It is made for `use`, so the rest of a
/// handler only runs for a valid token:
///
/// ```gleam
/// pub fn handle(request: Request(body)) -> Response(String) {
///   use _token <- gaseto_http.require_verified_bearer(
///     request,
///     key: public_key,
///     rules:,
///     realm: "api.example.com",
///     error_body: "",
///   )
///   response.new(200) |> response.set_body("Hello")
/// }
/// ```
pub fn require_verified_bearer(
  request: Request(request_body),
  key key: gaseto.PublicKey,
  rules rules: gaseto.Rules,
  realm realm: String,
  error_body error_body: response_body,
  next next: fn(gaseto.Token) -> Response(response_body),
) -> Response(response_body) {
  case verify_bearer(request, key:, rules:) {
    Ok(token) -> next(token)
    Error(error) -> error_response(error, realm:, body: error_body)
  }
}

/// Like `require_verified_bearer`, for a `local` token.
pub fn require_decrypted_bearer(
  request: Request(request_body),
  key key: gaseto.LocalKey,
  rules rules: gaseto.Rules,
  realm realm: String,
  error_body error_body: response_body,
  next next: fn(gaseto.Token) -> Response(response_body),
) -> Response(response_body) {
  case decrypt_bearer(request, key:, rules:) {
    Ok(token) -> next(token)
    Error(error) -> error_response(error, realm:, body: error_body)
  }
}

/// The token from the cookie with this name.
///
/// Most code wants `verify_cookie` or `decrypt_cookie` instead, which also
/// check the token.
pub fn cookie_token(
  request: Request(body),
  named name: String,
) -> Result(String, CookieError) {
  case list.key_filter(request.get_cookies(request), name) {
    [] | [""] -> Error(MissingCookie)
    [token] -> Ok(token)
    _ -> Error(RepeatedCookie)
  }
}

/// Reads the token from the cookie and verifies it as a `public` token. See
/// `gaseto.verify`.
pub fn verify_cookie(
  request: Request(body),
  named name: String,
  key key: gaseto.PublicKey,
  rules rules: gaseto.Rules,
) -> Result(gaseto.Token, CookieError) {
  use token <- result.try(cookie_token(request, named: name))
  gaseto.verify(token, key, rules) |> result.map_error(InvalidCookieToken)
}

/// Reads the token from the cookie and decrypts it as a `local` token. See
/// `gaseto.decrypt`.
pub fn decrypt_cookie(
  request: Request(body),
  named name: String,
  key key: gaseto.LocalKey,
  rules rules: gaseto.Rules,
) -> Result(gaseto.Token, CookieError) {
  use token <- result.try(cookie_token(request, named: name))
  gaseto.decrypt(token, key, rules) |> result.map_error(InvalidCookieToken)
}

/// Runs `next` with the token when the cookie's token verifies, and calls
/// `otherwise` with the error when it does not. A browser page often
/// redirects to a login page there, so the response is left to you. It is
/// made for `use`:
///
/// ```gleam
/// use _token <- gaseto_http.require_verified_cookie(
///   request,
///   named: "__Host-token",
///   key: public_key,
///   rules:,
///   otherwise: fn(_error) { redirect_to_login() },
/// )
/// ```
pub fn require_verified_cookie(
  request: Request(request_body),
  named name: String,
  key key: gaseto.PublicKey,
  rules rules: gaseto.Rules,
  otherwise otherwise: fn(CookieError) -> Response(response_body),
  next next: fn(gaseto.Token) -> Response(response_body),
) -> Response(response_body) {
  case verify_cookie(request, named: name, key:, rules:) {
    Ok(token) -> next(token)
    Error(error) -> otherwise(error)
  }
}

/// Like `require_verified_cookie`, for a `local` token.
pub fn require_decrypted_cookie(
  request: Request(request_body),
  named name: String,
  key key: gaseto.LocalKey,
  rules rules: gaseto.Rules,
  otherwise otherwise: fn(CookieError) -> Response(response_body),
  next next: fn(gaseto.Token) -> Response(response_body),
) -> Response(response_body) {
  case decrypt_cookie(request, named: name, key:, rules:) {
    Ok(token) -> next(token)
    Error(error) -> otherwise(error)
  }
}

/// Stores the token in a cookie for this long. The cookie is `HttpOnly`, so
/// scripts cannot read it, `Secure`, so it is only sent over HTTPS,
/// `SameSite=Lax`, and set for the whole site with `Path=/` and no `Domain`.
/// See the
/// [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies)
/// for what these mean. They also allow the `__Host-` name prefix, which
/// OWASP recommends. OWASP allows `SameSite=Lax` and prefers `Strict`.
/// `Lax` is used so that users who follow a link from another site arrive
/// logged in.
///
/// The token is written as it is, so pass one Gaseto made and read it back
/// with `verify_cookie` or `decrypt_cookie`. Wisp's own cookie functions
/// encode values differently. A lifetime under a second is rounded up to one
/// second, and a negative one counts as 0, which deletes the cookie.
///
/// ```gleam
/// response.new(200)
/// |> gaseto_http.set_token_cookie(
///   named: "__Host-token",
///   token:,
///   max_age: duration.hours(1),
/// )
/// ```
pub fn set_token_cookie(
  response: Response(body),
  named name: String,
  token token: String,
  max_age max_age: Duration,
) -> Response(body) {
  response.set_cookie(
    response,
    name,
    token,
    cookie_attributes(whole_seconds(max_age)),
  )
}

/// Tells the browser to delete the token cookie, for example when the user
/// logs out. A copy kept elsewhere still works until the token expires.
pub fn expire_token_cookie(
  response: Response(body),
  named name: String,
) -> Response(body) {
  response.set_cookie(response, name, "", cookie_attributes(0))
}

/// The HTTP status for the error: 400 for a malformed header, and 401
/// otherwise
/// ([RFC 6750, section 3.1](https://www.rfc-editor.org/rfc/rfc6750#section-3.1)).
pub fn error_status(error: BearerError) -> Int {
  case error {
    MalformedAuthorization -> 400
    MissingToken | InvalidToken(_) -> 401
  }
}

/// The `WWW-Authenticate` header that tells the client how to authenticate and
/// what went wrong
/// ([RFC 6750, section 3](https://www.rfc-editor.org/rfc/rfc6750#section-3)).
/// It starts with `Bearer`, the scheme the client should use, and the realm,
/// a name for what is protected, such as your API. An error code follows as
/// `error="..."`, except for a request without a token, as the RFC asks. The
/// reason a token was refused is not included, so it is not shared with the
/// client.
///
/// ```gleam
/// gaseto_http.challenge(MissingToken, realm: "api.example.com")
/// // -> "Bearer realm=\"api.example.com\""
/// ```
pub fn challenge(error: BearerError, realm realm: String) -> String {
  let scheme = "Bearer realm=" <> quoted(realm)
  case error {
    MissingToken -> scheme
    MalformedAuthorization -> scheme <> ", error=\"invalid_request\""
    InvalidToken(_) -> scheme <> ", error=\"invalid_token\""
  }
}

/// A response for the error, with its `error_status` and `challenge`.
///
/// ```gleam
/// gaseto_http.error_response(error, realm: "api.example.com", body: "")
/// // With Wisp:
/// gaseto_http.error_response(error, realm: "api.example.com", body: wisp.Text(""))
/// ```
pub fn error_response(
  error: BearerError,
  realm realm: String,
  body body: body,
) -> Response(body) {
  response.new(error_status(error))
  |> response.set_header("www-authenticate", challenge(error, realm:))
  |> response.set_body(body)
}

/// A response that hands a new token to the client, for example after a
/// login, in the form OAuth 2.0 uses
/// ([RFC 6749, section 5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1)).
/// The client then sends it back as a bearer token. The body is JSON:
///
/// ```json
/// {"access_token":"v4.public...","token_type":"Bearer","expires_in":900}
/// ```
///
/// `expires_in` is how long the token lasts. Pass the same duration the
/// claims were given with `gaseto.expires_in`, or one hour if they kept the
/// default. It is sent in whole seconds, rounded up, and never below 0. The
/// response is marked so that caches do not store the token, as the RFC
/// requires.
///
/// ```gleam
/// let assert Ok(token) = gaseto.sign(claims, secret_key)
/// gaseto_http.access_token_response(token, duration.minutes(15))
/// // With Wisp:
/// gaseto_http.access_token_response(token, duration.minutes(15))
/// |> response.map(wisp.Text)
/// ```
pub fn access_token_response(
  token: String,
  expires_in: Duration,
) -> Response(String) {
  let body =
    json.object([
      #("access_token", json.string(token)),
      #("token_type", json.string("Bearer")),
      #("expires_in", json.int(whole_seconds(expires_in))),
    ])
    |> json.to_string
  response.new(200)
  |> response.set_header("content-type", "application/json")
  |> response.set_header("cache-control", "no-store")
  |> response.set_header("pragma", "no-cache")
  |> response.set_body(body)
}

fn cookie_attributes(max_age_seconds: Int) -> cookie.Attributes {
  cookie.Attributes(
    max_age: Some(max_age_seconds),
    domain: option.None,
    path: Some("/"),
    secure: True,
    http_only: True,
    same_site: Some(cookie.Lax),
  )
}

/// The scheme name is followed by one or more spaces
/// ([RFC 6750, section 2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1)).
fn read_bearer(authorization: String) -> Result(String, BearerError) {
  case
    string.lowercase(string.slice(authorization, 0, 6)),
    string.drop_start(authorization, 6)
  {
    "bearer", " " <> credentials -> {
      let token = drop_spaces(credentials)
      case is_b64token(token) {
        True -> Ok(token)
        False -> Error(MalformedAuthorization)
      }
    }
    "bearer", "" | "bearer", "\t" <> _ -> Error(MalformedAuthorization)
    _, _ -> Error(MissingToken)
  }
}

/// An HTTP quoted string, with `"` and `\` escaped
/// ([RFC 9110, section 5.6.4](https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4)).
fn quoted(text: String) -> String {
  let escaped =
    text
    |> string.replace("\\", "\\\\")
    |> string.replace("\"", "\\\"")
  "\"" <> escaped <> "\""
}

/// Whole seconds, rounded up so that a fraction of a second does not become
/// 0, and never below 0.
fn whole_seconds(duration: Duration) -> Int {
  case duration.to_seconds_and_nanoseconds(duration) {
    #(seconds, _) if seconds < 0 -> 0
    #(seconds, 0) -> seconds
    #(seconds, _) -> seconds + 1
  }
}

fn drop_spaces(text: String) -> String {
  case text {
    " " <> rest -> drop_spaces(rest)
    _ -> text
  }
}

/// RFC 6750's `b64token`: at least one token character, then any number of
/// `=`.
fn is_b64token(token: String) -> Bool {
  case <<token:utf8>> {
    <<first, rest:bytes>> ->
      is_token_character(first) && token_characters_then_padding(rest)
    _ -> False
  }
}

fn token_characters_then_padding(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<"=":utf8, rest:bytes>> -> only_padding(rest)
    <<character, rest:bytes>> ->
      is_token_character(character) && token_characters_then_padding(rest)
    _ -> False
  }
}

fn only_padding(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<"=":utf8, rest:bytes>> -> only_padding(rest)
    _ -> False
  }
}

fn is_token_character(character: Int) -> Bool {
  case character {
    _ if character >= 0x41 && character <= 0x5A -> True
    _ if character >= 0x61 && character <= 0x7A -> True
    _ if character >= 0x30 && character <= 0x39 -> True
    0x2D | 0x2E | 0x5F | 0x7E | 0x2B | 0x2F -> True
    _ -> False
  }
}
