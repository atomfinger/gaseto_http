# gaseto_http

[![Package Version](https://img.shields.io/hexpm/v/gaseto_http)](https://hex.pm/packages/gaseto_http)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gaseto_http/)

Send, read and check PASETO tokens over HTTP, with
[Gaseto](https://github.com/atomfinger/gaseto). It works with any server built
on [gleam_http](https://hexdocs.pm/gleam_http/), such as Wisp and Mist.

## Installation

gaseto_http works alongside Gaseto, which provides the keys, claims and rules,
so add both:

```sh
gleam add gaseto gaseto_http
```

## Usage

### Logging in a user

Once the user has logged in, sign a token and hand it to them with
`access_token_response`. It answers in the form OAuth 2.0 uses
([RFC 6749, section 5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1)):

```gleam
import gaseto
import gaseto_http
import gleam/http/response.{type Response}
import gleam/time/duration

/// Call this once the user's password has been checked. The client gets:
///
///   HTTP/1.1 200 OK
///   content-type: application/json
///   cache-control: no-store
///   pragma: no-cache
///
///   {"access_token":"v4.public.eyJ...","token_type":"Bearer","expires_in":900}
///
pub fn log_in(
  user_identifier: String,
  secret_key: gaseto.SecretKey,
) -> Response(String) {
  let lifetime = duration.minutes(15)
  let claims =
    gaseto.new_claims()
    |> gaseto.with_issuer("login.example.com")
    |> gaseto.with_audience("api.example.com")
    |> gaseto.with_subject(user_identifier)
    |> gaseto.expires_in(lifetime)
  case gaseto.sign(claims, secret_key) {
    Ok(token) -> gaseto_http.access_token_response(token, lifetime)
    Error(_) -> response.new(500) |> response.set_body("")
  }
}
```

### Checking a request

The client sends the token back on later requests, as a bearer token
([RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)):
`Authorization: Bearer <token>`. Check it with `require_verified_bearer`.
The rest of the handler only runs for a valid token:

```gleam
import gaseto
import gaseto_http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}

pub fn handle(
  request: Request(body),
  public_key: gaseto.PublicKey,
) -> Response(String) {
  // Only tokens from our login service, made for this API
  let rules =
    gaseto.new_rules()
    |> gaseto.issued_by("login.example.com")
    |> gaseto.for_audience("api.example.com")
  use _token <- gaseto_http.require_verified_bearer(
    request,
    key: public_key,
    rules:,
    realm: "api.example.com",
    error_body: "",
  )
  response.new(200) |> response.set_body("Hello, user")
}
```

A refused request gets the status and `WWW-Authenticate` header RFC 6750
describes. The reason a token was refused is not sent to the client. To read
the token yourself, for example its subject, use `verify_bearer`, or keep
the token that `require_verified_bearer` passes on.

### Cookies

For a browser, the token can live in a cookie instead. `set_token_cookie`
stores it, `verify_cookie` or `decrypt_cookie` read it back, and
`expire_token_cookie` deletes it on logout:

```gleam
response.new(200)
|> gaseto_http.set_token_cookie(
  named: "__Host-token",
  token:,
  max_age: duration.hours(1),
)
```

Checking it works the same way, except that you choose the response for a
refused request, since a browser page usually redirects to a login page:

```gleam
use _token <- gaseto_http.require_verified_cookie(
  request,
  named: "__Host-token",
  key: public_key,
  rules:,
  otherwise: fn(_error) { redirect_to_login() },
)
```

The cookie is `HttpOnly`, `Secure` and `SameSite=Lax`. See the
[OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies)
for what these mean, and the
[OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
for how to protect requests that change something.

Further documentation can be found at <https://hexdocs.pm/gaseto_http>.

## Development

```sh
gleam test  # Run the tests
```
