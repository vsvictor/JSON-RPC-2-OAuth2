# Okta

## English

**Protocol:** OIDC authorization-code flow using an Okta authorization-server
issuer.

1. Configure an Okta OIDC app and HTTPS callback. Set `issuer_url` to the
   trusted authorization-server issuer (often an `/oauth2/{serverId}` URL).
2. The server performs OIDC discovery and requires the discovery issuer to
   match. Authorization/token/userinfo endpoints must be HTTPS and on the
   issuer origin.
3. Redirect with `openid profile email`, state, and PKCE; validate state from
   the server-side session.
4. Exchange the code and retrieve userinfo. Use `sub`; provision a new account
   only when `email_verified` is true.
5. Persist `(okta, sub)` and issue local tokens.

Issuer selection is security-sensitive. Keep the configured issuer in trusted
server configuration, not in untrusted callback parameters.

## Українська

**Протокол:** OIDC authorization-code з issuer authorization server Okta.

1. Налаштуйте Okta OIDC app і HTTPS callback. Задайте `issuer_url` як довірений
   issuer authorization server (часто URL `/oauth2/{serverId}`).
2. Сервер виконує OIDC discovery і вимагає точного збігу issuer. Authorization,
   token і userinfo endpoints мають бути HTTPS та належати origin issuer.
3. Перенаправте зі scope `openid profile email`, state і PKCE; перевірте state
   із серверної сесії.
4. Обміняйте код і отримайте userinfo. Використовуйте `sub`; новий акаунт
   створюється лише з `email_verified: true`.
5. Збережіть `(okta, sub)` і видайте локальні токени.

Вибір issuer критично важливий для безпеки. Зберігайте його у довіреній
серверній конфігурації, а не в недовірених параметрах callback.
