# LinkedIn

## English

**Protocol:** LinkedIn OpenID Connect authorization-code flow.

1. Enable the Sign In with LinkedIn using OpenID Connect product and register
   the exact HTTPS redirect URI.
2. Request `openid profile email`, state, and PKCE S256.
3. Validate state in the server-side callback session, exchange the code, and
   request LinkedIn OIDC userinfo.
4. Use `sub` as the stable provider subject. Provision only with
   `email_verified: true`.
5. Persist `(linkedin, sub)` and issue local tokens.

Ensure the LinkedIn app has the required product approval; scopes alone do not
grant app access.

## Українська

**Протокол:** LinkedIn OpenID Connect authorization-code.

1. Увімкніть продукт Sign In with LinkedIn using OpenID Connect і зареєструйте
   точний HTTPS redirect URI.
2. Запитайте `openid profile email`, state та PKCE S256.
3. Перевірте state у серверній callback-сесії, обміняйте код і запитайте
   LinkedIn OIDC userinfo.
4. Використовуйте `sub` як стабільний subject. Створюйте акаунт лише за
   `email_verified: true`.
5. Збережіть `(linkedin, sub)` і видайте локальні токени.

Переконайтеся, що LinkedIn app має схвалений потрібний продукт: наявність
scope сама по собі не надає доступу застосунку.
