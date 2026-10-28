# Slack

## English

**Protocol:** Slack OpenID Connect authorization-code flow.

1. Configure a Slack app with an HTTPS redirect URL and OIDC scopes
   `openid profile email`.
2. Redirect to Slack with state and PKCE S256; retain both in the server
   session.
3. Exchange the code and call Slack's OIDC `userinfo` endpoint.
4. Use OIDC `sub`; only auto-provision when `email_verified` is true.
5. Persist the provider subject and issue local PASETO tokens.

This is Slack Sign in with Slack (OIDC), not the separate workspace
installation/ bot-token OAuth flow.

## Українська

**Протокол:** Slack OpenID Connect authorization-code.

1. Налаштуйте Slack app з HTTPS redirect URL і OIDC scopes
   `openid profile email`.
2. Перенаправте на Slack зі state та PKCE S256; збережіть їх у серверній сесії.
3. Обміняйте код і викличте OIDC `userinfo` endpoint Slack.
4. Використовуйте OIDC `sub`; автоматичне створення акаунта дозволене лише з
   `email_verified: true`.
5. Збережіть subject провайдера та видайте локальні PASETO-токени.

Це Slack Sign in with Slack (OIDC), а не окремий OAuth-потік встановлення
workspace/отримання bot token.
