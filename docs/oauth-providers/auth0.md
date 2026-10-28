# Auth0

## English

**Protocol:** OIDC authorization-code flow using Auth0 tenant discovery.

1. Set `issuer_url` to the exact HTTPS Auth0 tenant issuer, including any
   regional/custom domain and trailing path required by the tenant.
2. The server fetches `/.well-known/openid-configuration`; its issuer must
   match exactly. Authorization/token/userinfo endpoints must be HTTPS and
   share the configured issuer origin.
3. Redirect with `openid profile email`, state, and PKCE. Store and validate
   callback state in the server session.
4. Exchange the code and request the discovered userinfo endpoint. Use `sub`
   and require `email_verified: true` to provision a new local account.
5. Persist `(auth0, sub)` and issue local tokens.

Use only a trusted Auth0 issuer. Do not allow arbitrary user-controlled issuer
URLs.

## Українська

**Протокол:** OIDC authorization-code із discovery tenant Auth0.

1. Задайте `issuer_url` як точний HTTPS issuer tenant Auth0, включно з
   регіональним/custom domain і потрібним шляхом.
2. Сервер отримує `/.well-known/openid-configuration`; issuer має точно
   збігатися. Authorization/token/userinfo endpoints мають бути HTTPS і мати
   origin налаштованого issuer.
3. Перенаправте зі scope `openid profile email`, state і PKCE. Збережіть і
   перевірте state callback у серверній сесії.
4. Обміняйте код і запитайте знайдений userinfo endpoint. Використовуйте `sub`;
   для нового акаунта потрібен `email_verified: true`.
5. Збережіть `(auth0, sub)` і видайте локальні токени.

Використовуйте лише довірений Auth0 issuer. Не дозволяйте задавати довільний
issuer із користувацьких параметрів.
