import gaseto.{PasetoV4}
import gaseto/error
import gaseto_http.{
  InvalidCookieToken, InvalidToken, MalformedAuthorization, MissingCookie,
  MissingToken, RepeatedCookie,
}
import gleam/dict
import gleam/dynamic/decode
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{Some}
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import gleeunit

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn the_bearer_token_is_read_test() -> Nil {
  use authorization <- list.each([
    "Bearer abc.DEF-123_~+/", "bearer abc.DEF-123_~+/", "BEARER abc.DEF-123_~+/",
    "Bearer    abc.DEF-123_~+/", " Bearer abc.DEF-123_~+/ ",
    "\tBearer abc.DEF-123_~+/\t",
  ])
  assert gaseto_http.bearer_token(with_authorization(authorization))
    == Ok("abc.DEF-123_~+/")
}

pub fn padding_is_allowed_at_the_end_only_test() -> Nil {
  assert gaseto_http.bearer_token(with_authorization("Bearer abc=="))
    == Ok("abc==")
  assert gaseto_http.bearer_token(with_authorization("Bearer a=bc"))
    == Error(MalformedAuthorization)
}

pub fn a_request_without_a_bearer_token_is_missing_one_test() -> Nil {
  assert gaseto_http.bearer_token(request.new()) == Error(MissingToken)
  use authorization <- list.each(["Basic dXNlcjpwYXNz", "Token abc", ""])
  assert gaseto_http.bearer_token(with_authorization(authorization))
    == Error(MissingToken)
}

pub fn a_malformed_bearer_header_is_refused_test() -> Nil {
  use authorization <- list.each([
    "Bearer", "Bearer ", "Bearer a b", "Bearer ===", "Bearer abc\"",
    "Bearer åbc", "Bearer\tabc", "Bearer \t",
  ])
  assert gaseto_http.bearer_token(with_authorization(authorization))
    == Error(MalformedAuthorization)
}

pub fn a_public_bearer_token_is_verified_test() -> Nil {
  let secret_key = gaseto.generate_secret_key(PasetoV4)
  let assert Ok(token) =
    gaseto.new_claims()
    |> gaseto.with_subject("user-42")
    |> gaseto.sign(secret_key)
  let assert Ok(verified) =
    gaseto_http.verify_bearer(
      with_authorization("Bearer " <> token),
      key: gaseto.secret_key_to_public_key(secret_key),
      rules: gaseto.new_rules(),
    )
  assert gaseto.subject(verified) == Some("user-42")
}

pub fn a_local_bearer_token_is_decrypted_test() -> Nil {
  let key = gaseto.generate_local_key(PasetoV4)
  let assert Ok(token) =
    gaseto.new_claims()
    |> gaseto.with_subject("user-42")
    |> gaseto.encrypt(key)
  let assert Ok(decrypted) =
    gaseto_http.decrypt_bearer(
      with_authorization("Bearer " <> token),
      key:,
      rules: gaseto.new_rules(),
    )
  assert gaseto.subject(decrypted) == Some("user-42")
}

pub fn a_refused_token_keeps_gasetos_reason_test() -> Nil {
  let secret_key = gaseto.generate_secret_key(PasetoV4)
  let other_public_key =
    gaseto.secret_key_to_public_key(gaseto.generate_secret_key(PasetoV4))
  let an_hour_ago = timestamp.add(timestamp.system_time(), duration.hours(-1))
  let assert Ok(valid) = gaseto.sign(gaseto.new_claims(), secret_key)
  let assert Ok(expired) =
    gaseto.new_claims()
    |> gaseto.with_issued_at(timestamp.add(an_hour_ago, duration.hours(-1)))
    |> gaseto.with_expires_at(an_hour_ago)
    |> gaseto.sign(secret_key)

  assert gaseto_http.verify_bearer(
      with_authorization("Bearer " <> valid),
      key: other_public_key,
      rules: gaseto.new_rules(),
    )
    == Error(InvalidToken(error.TokenNotAuthentic))
  let assert Error(InvalidToken(error.Expired(_))) =
    gaseto_http.verify_bearer(
      with_authorization("Bearer " <> expired),
      key: gaseto.secret_key_to_public_key(secret_key),
      rules: gaseto.new_rules(),
    )
  Nil
}

pub fn a_missing_header_is_reported_before_any_key_is_used_test() -> Nil {
  let key = gaseto.generate_local_key(PasetoV4)
  assert gaseto_http.decrypt_bearer(
      request.new(),
      key:,
      rules: gaseto.new_rules(),
    )
    == Error(MissingToken)
}

pub fn each_error_gets_the_rfc_6750_status_and_challenge_test() -> Nil {
  use #(error, status, challenge) <- list.each([
    #(MissingToken, 401, "Bearer realm=\"api\""),
    #(
      MalformedAuthorization,
      400,
      "Bearer realm=\"api\", error=\"invalid_request\"",
    ),
    #(
      InvalidToken(error.TokenNotAuthentic),
      401,
      "Bearer realm=\"api\", error=\"invalid_token\"",
    ),
  ])
  let response = gaseto_http.error_response(error, realm: "api", body: "")
  assert response.status == status
  assert response.get_header(response, "www-authenticate") == Ok(challenge)
  assert response.body == ""
}

pub fn the_reason_a_token_was_refused_is_not_shared_test() -> Nil {
  let expired = InvalidToken(error.Expired(timestamp.from_unix_seconds(0)))
  assert gaseto_http.challenge(expired, realm: "api")
    == "Bearer realm=\"api\", error=\"invalid_token\""
}

pub fn the_realm_is_quoted_test() -> Nil {
  assert gaseto_http.challenge(MissingToken, realm: "say \"hi\" \\o/")
    == "Bearer realm=\"say \\\"hi\\\" \\\\o/\""
}

pub fn the_access_token_response_follows_rfc_6749_test() -> Nil {
  let response =
    gaseto_http.access_token_response("v4.public.abc", duration.minutes(15))
  assert response.status == 200
  assert response.get_header(response, "content-type") == Ok("application/json")
  assert response.get_header(response, "cache-control") == Ok("no-store")
  assert response.get_header(response, "pragma") == Ok("no-cache")
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use expires_in <- decode.field("expires_in", decode.int)
    decode.success(#(access_token, token_type, expires_in))
  }
  assert json.parse(response.body, decoder)
    == Ok(#("v4.public.abc", "Bearer", 900))
}

pub fn the_access_token_response_holds_only_the_rfc_fields_test() -> Nil {
  let response =
    gaseto_http.access_token_response("v4.public.abc", duration.hours(1))
  let assert Ok(fields) =
    json.parse(response.body, decode.dict(decode.string, decode.dynamic))
  assert dict.keys(fields) |> list.sort(string.compare)
    == ["access_token", "expires_in", "token_type"]
}

pub fn a_token_from_the_response_is_accepted_as_a_bearer_token_test() -> Nil {
  let secret_key = gaseto.generate_secret_key(PasetoV4)
  let assert Ok(token) =
    gaseto.new_claims()
    |> gaseto.with_subject("user-42")
    |> gaseto.sign(secret_key)
  let response = gaseto_http.access_token_response(token, duration.hours(1))
  let assert Ok(sent_token) =
    json.parse(response.body, decode.at(["access_token"], decode.string))
  let assert Ok(verified) =
    gaseto_http.verify_bearer(
      with_authorization("Bearer " <> sent_token),
      key: gaseto.secret_key_to_public_key(secret_key),
      rules: gaseto.new_rules(),
    )
  assert gaseto.subject(verified) == Some("user-42")
}

pub fn the_cookie_token_is_read_test() -> Nil {
  let request =
    request.new() |> request.set_cookie("__Host-token", "v4.local.abc")
  assert gaseto_http.cookie_token(request, named: "__Host-token")
    == Ok("v4.local.abc")
  assert gaseto_http.cookie_token(request, named: "other")
    == Error(MissingCookie)
  assert gaseto_http.cookie_token(request.new(), named: "__Host-token")
    == Error(MissingCookie)
}

pub fn a_cookie_set_by_set_token_cookie_is_read_back_test() -> Nil {
  let key = gaseto.generate_local_key(PasetoV4)
  let assert Ok(token) =
    gaseto.new_claims()
    |> gaseto.with_subject("user-42")
    |> gaseto.encrypt(key)
  let response =
    response.new(200)
    |> gaseto_http.set_token_cookie(
      named: "__Host-token",
      token:,
      max_age: duration.hours(1),
    )
  // As a browser would send it back
  let assert Ok(#("__Host-token", value)) =
    response.get_cookies(response) |> list.first
  let request = request.new() |> request.set_cookie("__Host-token", value)
  let assert Ok(decrypted) =
    gaseto_http.decrypt_cookie(
      request,
      named: "__Host-token",
      key:,
      rules: gaseto.new_rules(),
    )
  assert gaseto.subject(decrypted) == Some("user-42")
}

pub fn a_public_cookie_token_is_verified_test() -> Nil {
  let secret_key = gaseto.generate_secret_key(PasetoV4)
  let assert Ok(token) =
    gaseto.new_claims()
    |> gaseto.with_subject("user-42")
    |> gaseto.sign(secret_key)
  let request = request.new() |> request.set_cookie("__Host-token", token)
  let assert Ok(verified) =
    gaseto_http.verify_cookie(
      request,
      named: "__Host-token",
      key: gaseto.secret_key_to_public_key(secret_key),
      rules: gaseto.new_rules(),
    )
  assert gaseto.subject(verified) == Some("user-42")
}

pub fn a_refused_cookie_token_keeps_gasetos_reason_test() -> Nil {
  let key = gaseto.generate_local_key(PasetoV4)
  let other_key = gaseto.generate_local_key(PasetoV4)
  let assert Ok(token) = gaseto.encrypt(gaseto.new_claims(), other_key)
  let request = request.new() |> request.set_cookie("__Host-token", token)
  assert gaseto_http.decrypt_cookie(
      request,
      named: "__Host-token",
      key:,
      rules: gaseto.new_rules(),
    )
    == Error(InvalidCookieToken(error.TokenNotAuthentic))
}

pub fn the_token_cookie_has_the_owasp_attributes_test() -> Nil {
  let response =
    response.new(200)
    |> gaseto_http.set_token_cookie(
      named: "__Host-token",
      token: "v4.local.abc",
      max_age: duration.minutes(15),
    )
  let assert Ok(set_cookie) = response.get_header(response, "set-cookie")
  assert string.starts_with(set_cookie, "__Host-token=v4.local.abc")
  use attribute <- list.each([
    "Max-Age=900", "Path=/", "Secure", "HttpOnly", "SameSite=Lax",
  ])
  assert string.contains(set_cookie, attribute) as attribute
  assert !string.contains(set_cookie, "Domain")
}

pub fn expiring_the_token_cookie_takes_effect_now_test() -> Nil {
  let response =
    response.new(200)
    |> gaseto_http.expire_token_cookie(named: "__Host-token")
  let assert Ok(set_cookie) = response.get_header(response, "set-cookie")
  assert string.starts_with(set_cookie, "__Host-token=;")
  assert string.contains(set_cookie, "Max-Age=0")
  // The same Path and no Domain, so the browser replaces the cookie it has,
  // and Secure, so a __Host- name is accepted
  assert string.contains(set_cookie, "Path=/")
  assert string.contains(set_cookie, "Secure")
}

pub fn require_verified_bearer_runs_the_handler_for_a_valid_token_test() -> Nil {
  let secret_key = gaseto.generate_secret_key(PasetoV4)
  let assert Ok(token) =
    gaseto.new_claims()
    |> gaseto.with_subject("user-42")
    |> gaseto.sign(secret_key)
  let response = {
    use token <- gaseto_http.require_verified_bearer(
      with_authorization("Bearer " <> token),
      key: gaseto.secret_key_to_public_key(secret_key),
      rules: gaseto.new_rules(),
      realm: "test",
      error_body: "refused",
    )
    let assert Some(subject) = gaseto.subject(token)
    response.new(200) |> response.set_body(subject)
  }
  assert response.status == 200
  assert response.body == "user-42"
}

pub fn require_verified_bearer_answers_a_refused_request_itself_test() -> Nil {
  let public_key =
    gaseto.secret_key_to_public_key(gaseto.generate_secret_key(PasetoV4))
  let response = {
    use _token <- gaseto_http.require_verified_bearer(
      request.new(),
      key: public_key,
      rules: gaseto.new_rules(),
      realm: "test",
      error_body: "refused",
    )
    panic as "the handler must not run without a token"
  }
  assert response
    == gaseto_http.error_response(MissingToken, realm: "test", body: "refused")
}

pub fn require_decrypted_bearer_checks_a_local_token_test() -> Nil {
  let key = gaseto.generate_local_key(PasetoV4)
  let other_key = gaseto.generate_local_key(PasetoV4)
  let assert Ok(token) = gaseto.encrypt(gaseto.new_claims(), key)
  let handle = fn(key) {
    use _token <- gaseto_http.require_decrypted_bearer(
      with_authorization("Bearer " <> token),
      key:,
      rules: gaseto.new_rules(),
      realm: "test",
      error_body: "",
    )
    response.new(200)
  }
  assert handle(key).status == 200
  assert handle(other_key).status == 401
}

pub fn require_verified_cookie_leaves_the_refusal_to_the_caller_test() -> Nil {
  let secret_key = gaseto.generate_secret_key(PasetoV4)
  let assert Ok(token) = gaseto.sign(gaseto.new_claims(), secret_key)
  let handle = fn(request) {
    use _token <- gaseto_http.require_verified_cookie(
      request,
      named: "__Host-token",
      key: gaseto.secret_key_to_public_key(secret_key),
      rules: gaseto.new_rules(),
      otherwise: fn(_error) {
        response.new(303) |> response.set_header("location", "/login")
      },
    )
    response.new(200)
  }
  assert handle(request.new() |> request.set_cookie("__Host-token", token)).status
    == 200
  let redirected = handle(request.new())
  assert redirected.status == 303
  assert response.get_header(redirected, "location") == Ok("/login")
}

pub fn require_decrypted_cookie_passes_the_error_on_test() -> Nil {
  let key = gaseto.generate_local_key(PasetoV4)
  let response = {
    use _token <- gaseto_http.require_decrypted_cookie(
      request.new(),
      named: "__Host-token",
      key:,
      rules: gaseto.new_rules(),
      otherwise: fn(error) {
        assert error == MissingCookie
        response.new(303)
      },
    )
    response.new(200)
  }
  assert response.status == 303
}

pub fn a_repeated_authorization_header_is_refused_test() -> Nil {
  let request =
    request.new()
    |> request.prepend_header("authorization", "Bearer abc")
    |> request.prepend_header("authorization", "Bearer def")
  assert gaseto_http.bearer_token(request) == Error(MalformedAuthorization)
}

pub fn require_verified_bearer_answers_400_for_a_malformed_header_test() -> Nil {
  let public_key =
    gaseto.secret_key_to_public_key(gaseto.generate_secret_key(PasetoV4))
  let response = {
    use _token <- gaseto_http.require_verified_bearer(
      with_authorization("Bearer a b"),
      key: public_key,
      rules: gaseto.new_rules(),
      realm: "test",
      error_body: "",
    )
    panic as "the handler must not run for a malformed header"
  }
  assert response.status == 400
}

pub fn a_repeated_cookie_is_refused_test() -> Nil {
  // A page on another subdomain can add its own cookie with the same name
  let request =
    request.new()
    |> request.set_header(
      "cookie",
      "token=v4.local.attacker; token=v4.local.user",
    )
  assert gaseto_http.cookie_token(request, named: "token")
    == Error(RepeatedCookie)
}

pub fn an_empty_cookie_counts_as_missing_test() -> Nil {
  let request = request.new() |> request.set_cookie("__Host-token", "")
  assert gaseto_http.cookie_token(request, named: "__Host-token")
    == Error(MissingCookie)
}

pub fn require_decrypted_cookie_passes_a_refused_token_on_test() -> Nil {
  let other_key = gaseto.generate_local_key(PasetoV4)
  let assert Ok(token) = gaseto.encrypt(gaseto.new_claims(), other_key)
  let response = {
    use _token <- gaseto_http.require_decrypted_cookie(
      request.new() |> request.set_cookie("__Host-token", token),
      named: "__Host-token",
      key: gaseto.generate_local_key(PasetoV4),
      rules: gaseto.new_rules(),
      otherwise: fn(error) {
        assert error == InvalidCookieToken(error.TokenNotAuthentic)
        response.new(303)
      },
    )
    response.new(200)
  }
  assert response.status == 303
}

pub fn a_lifetime_is_rounded_up_to_whole_seconds_test() -> Nil {
  use #(lifetime, seconds) <- list.each([
    #(duration.milliseconds(500), 1),
    #(duration.milliseconds(1500), 2),
    #(duration.seconds(90), 90),
    #(duration.seconds(0), 0),
    #(duration.milliseconds(-500), 0),
    #(duration.seconds(-90), 0),
  ])
  let cookie_response =
    response.new(200)
    |> gaseto_http.set_token_cookie(
      named: "__Host-token",
      token: "v4.local.abc",
      max_age: lifetime,
    )
  let assert Ok(set_cookie) = response.get_header(cookie_response, "set-cookie")
  let max_age = "Max-Age=" <> int.to_string(seconds) <> ";"
  assert string.contains(set_cookie <> ";", max_age) as max_age
  let token_response =
    gaseto_http.access_token_response("v4.public.abc", lifetime)
  assert json.parse(token_response.body, decode.at(["expires_in"], decode.int))
    == Ok(seconds)
}

fn with_authorization(authorization: String) -> request.Request(String) {
  request.new() |> request.set_header("authorization", authorization)
}
