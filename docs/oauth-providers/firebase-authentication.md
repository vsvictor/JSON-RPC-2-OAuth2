# Firebase Authentication

## English

**Protocol:** Firebase client SDK sign-in followed by server-side Firebase ID
token validation; this is not an OAuth authorization-code redirect.

1. Complete provider sign-in with Firebase Authentication on the client.
2. Send the resulting Firebase ID token to the application over HTTPS.
3. Call `JsonRpcAuthServer::handle_firebase_id_token(project_id, id_token)`.
   The library validates RS256 signature via Google's Secure Token JWKS and
   checks `iss`, `aud`, `sub`, and expiry.
4. Persist `(firebase_authentication, sub)`. A new local account requires
   `email_verified: true`; an identity already explicitly linked can sign in
   even when email is absent.
5. The server issues local PASETO tokens; Firebase tokens are not returned as
   this service's access tokens.

The Firebase project ID is required. Never trust decoded token claims without
the signature and issuer/audience checks performed by the library.

## Українська

**Протокол:** вхід через клієнтський Firebase SDK із подальшою серверною
перевіркою Firebase ID token; це не redirect-потік OAuth authorization-code.

1. Виконайте вхід через Firebase Authentication на клієнті.
2. Передайте отриманий Firebase ID token застосунку через HTTPS.
3. Викличте `JsonRpcAuthServer::handle_firebase_id_token(project_id, id_token)`.
   Бібліотека перевіряє підпис RS256 через Secure Token JWKS Google та claims
   `iss`, `aud`, `sub` і строк дії.
4. Збережіть `(firebase_authentication, sub)`. Для нового локального акаунта
   потрібен `email_verified: true`; раніше явно прив’язаний акаунт може входити
   і без email.
5. Сервер видає локальні PASETO-токени; Firebase token не є access token цього
   сервісу.

Потрібен Firebase project ID. Не довіряйте декодованим claims без перевірки
підпису, issuer та audience, яку виконує бібліотека.
