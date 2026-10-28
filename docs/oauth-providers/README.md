# OAuth2 provider flows / OAuth2-потоки провайдерів

Each provider has a separate bilingual flow description. These describe the
library's current behavior and security boundaries.

Кожен провайдер має окремий двомовний опис потоку. У файлах зафіксовано
поточну поведінку бібліотеки та межі її гарантій безпеки.

| Provider | Flow |
|---|---|
| Google | [google.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/google.md) |
| Firebase Authentication | [firebase-authentication.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/firebase-authentication.md) |
| Apple | [apple.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/apple.md) |
| Microsoft (Azure AD / Identity Platform) | [microsoft.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/microsoft.md) |
| Facebook (Meta) | [facebook.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/facebook.md) |
| X | [x.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/x.md) |
| LinkedIn | [linkedin.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/linkedin.md) |
| Slack | [slack.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/slack.md) |
| GitHub | [github.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/github.md) |
| GitLab | [gitlab.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/gitlab.md) |
| Bitbucket | [bitbucket.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/bitbucket.md) |
| Discord | [discord.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/discord.md) |
| Twitch | [twitch.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/twitch.md) |
| Spotify | [spotify.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/spotify.md) |
| Auth0 | [auth0.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/auth0.md) |
| Okta | [okta.md](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/okta.md) |

`JsonRpcAuthServer::handle_provider_callback` exchanges OAuth authorization
codes and routes verified identities to the selected storage backend.
`handle_firebase_id_token` handles Firebase's client-SDK token flow.
`handle_provider_link` and `link_firebase_id_token` link an identity to an
already authenticated local user. Linking endpoints must only be called after
the application has authenticated that local user.

Метод `JsonRpcAuthServer::handle_provider_callback` обмінює OAuth-код і
передає перевірену ідентичність вибраному бекенду. Для Firebase, де токен
отримується через клієнтський SDK, призначений `handle_firebase_id_token`.
Методи `handle_provider_link` і `link_firebase_id_token` прив’язують
ідентичність до вже автентифікованого локального користувача. Викликати
прив’язування можна лише після автентифікації локального користувача застосунком.

All storage backends persist the unique `(provider, subject)` identity. A
verified provider email may provision a new local account. An unverified or
missing email may authenticate an identity that was explicitly linked earlier,
but never provisions a new account. A matching email alone never links accounts.

Усі бекенди зберігають унікальну пару `(provider, subject)`. Підтверджений
провайдером email може створити новий локальний акаунт. Відсутній або
непідтверджений email дозволяє вхід лише для ідентичності, яку раніше явно
прив’язали; новий акаунт так не створюється. Збіг email сам по собі ніколи не
об’єднує акаунти.
