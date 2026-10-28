# Microsoft (Azure AD / Identity Platform)

## English

**Protocol:** OIDC authorization-code flow with tenant-specific discovery.

1. Set `issuer_url` to the tenant's HTTPS v2 issuer on
   `login.microsoftonline.com`; configure a matching redirect URI and client.
2. The library retrieves OIDC discovery and checks the issuer and discovered
   authorization/token endpoints. The userinfo endpoint may be Microsoft Graph.
3. Redirect with `openid profile email`, state, and PKCE; validate state from
   the server-side session in the callback.
4. Exchange the code and retrieve userinfo. Use `sub` as the provider subject.
5. A new local account is created only if the response contains an email and
   `email_verified: true`. Microsoft tenants often omit that claim; explicitly
   link such an identity while the local user is authenticated.

Never use an unverified `mail` or `userPrincipalName` as proof of email
ownership. Discovery endpoints must be HTTPS and constrained to the configured
issuer origin (Graph is allowed for userinfo).

## Українська

**Протокол:** OIDC authorization-code із discovery для конкретного tenant.

1. Задайте `issuer_url` як HTTPS v2 issuer tenant на
   `login.microsoftonline.com`; налаштуйте відповідний redirect URI та client.
2. Бібліотека отримує OIDC discovery і перевіряє issuer та authorization/token
   endpoints. Userinfo може бути Microsoft Graph.
3. Виконайте redirect зі scope `openid profile email`, state і PKCE; у callback
   перевірте state зі значенням серверної сесії.
4. Обміняйте код і отримайте userinfo. Використовуйте `sub` як subject.
5. Новий локальний акаунт створюється лише за наявності email та
   `email_verified: true`. Microsoft tenant часто не повертає цей claim; тоді
   явно прив’яжіть ідентичність, поки локальний користувач автентифікований.

Не вважайте непідтверджені `mail` чи `userPrincipalName` доказом володіння
email. Discovery endpoints мають бути HTTPS і належати origin issuer; для
userinfo допускається Graph.
