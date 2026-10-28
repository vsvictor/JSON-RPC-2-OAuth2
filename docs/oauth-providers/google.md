# Google

## English

**Protocol:** OpenID Connect authorization-code flow with PKCE.

1. Redirect to Google's OIDC authorization endpoint with `openid email profile`,
   `state`, and an S256 PKCE challenge.
2. Keep `state` and the verifier in a server-side session. On callback compare
   the returned state with that session value.
3. Exchange the code at Google's token endpoint and query OIDC userinfo.
4. Use the OIDC `sub` as the provider subject. Provision a local account only
   when userinfo includes an email and `email_verified: true`.
5. Persist `(google, sub)` and issue local PASETO tokens.

Use the Google OAuth client ID/secret and an exact HTTPS callback URL.
`handle_provider_callback` does not implicitly link by email.

## Українська

**Протокол:** OpenID Connect authorization-code із PKCE.

1. Перенаправте користувача на OIDC endpoint Google зі scope `openid email
   profile`, параметром `state` та S256 PKCE challenge.
2. Збережіть `state` і verifier у серверній сесії; у callback звірте повернений
   `state` зі значенням сесії.
3. Обміняйте код на token endpoint Google і отримайте OIDC userinfo.
4. Використовуйте OIDC `sub` як ідентифікатор провайдера. Новий локальний
   акаунт створюється лише за наявності email і `email_verified: true`.
5. Збережіть `(google, sub)` і видайте локальні PASETO-токени.

Потрібні Google OAuth client ID/secret і точний HTTPS callback URL.
`handle_provider_callback` не прив’язує акаунти лише за email.
