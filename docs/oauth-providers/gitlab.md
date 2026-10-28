# GitLab

## English

**Protocol:** GitLab OpenID Connect authorization-code flow.

1. Set `issuer_url` to the HTTPS GitLab OIDC issuer (`https://gitlab.com` or
   the configured self-managed instance) and register a matching callback.
2. The server discovers the issuer's authorization, token, and userinfo URLs.
   Discovery issuer and token endpoints are validated against the issuer.
3. Redirect with `openid profile email`, state, and PKCE; validate callback
   state, exchange the code, then retrieve userinfo.
4. Use `sub`; new account provisioning requires `email_verified: true`.
5. Persist `(gitlab, sub)` and issue local tokens.

Only configure a trusted issuer controlled by your organization; discovery is
performed from that URL.

## Українська

**Протокол:** GitLab OpenID Connect authorization-code.

1. Задайте `issuer_url` як HTTPS OIDC issuer GitLab (`https://gitlab.com` або
   налаштований self-managed instance) і зареєструйте відповідний callback.
2. Сервер знаходить authorization, token і userinfo URLs через discovery.
   Issuer і token endpoints перевіряються щодо origin issuer.
3. Перенаправте зі scope `openid profile email`, state та PKCE; перевірте state
   у callback, обміняйте код і отримайте userinfo.
4. Використовуйте `sub`; для нового акаунта потрібен `email_verified: true`.
5. Збережіть `(gitlab, sub)` і видайте локальні токени.

Налаштовуйте лише довірений issuer, контрольований вашою організацією;
discovery виконується за цією адресою.
