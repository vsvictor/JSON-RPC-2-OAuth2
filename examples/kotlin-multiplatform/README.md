# Kotlin Multiplatform client example

This shared Kotlin module calls the JSON-RPC methods registered by
`register_auth_methods`. It demonstrates registration, password login, refresh,
and profile update over the application's HTTPS JSON-RPC endpoint.

## Use in a KMP application

Build the shared Android and common source sets from this directory with
`./gradlew :shared:compileCommonMainKotlinMetadata :shared:compileAndroidMain`.
An Android SDK is required for the Android target; compile the iOS targets on
macOS with Xcode installed.

Add the `shared` module to your project, then include a Ktor HTTP engine in the
platform source sets. For example, use `ktor-client-android` in `androidMain`
and `ktor-client-darwin` in `iosMain` at the same Ktor version as the common
dependencies. The sample uses the Android KMP library plugin and requires
Android Gradle Plugin 9.1. Construct the shared client with the platform engine:

```kotlin
// In androidMain:
import io.ktor.client.engine.android.Android

val auth = JsonRpcAuthClient("https://api.example.com/json-rpc", Android.create())

val user = auth.register("reader@example.test", "a long password")
val tokens = auth.login(user.email, "a long password")
val updated = auth.updateProfile(
    accessToken = tokens.access_token,
    profile = mapOf("display_name" to "Reader"),
)
auth.close()
```

On iOS, import `io.ktor.client.engine.darwin.Darwin` and pass `Darwin.create()`
from `iosMain`. In a real app, keep the
access/refresh tokens in platform-secure storage (Android Keystore and iOS
Keychain). Call `refresh(tokens.refresh_token)` when renewing a session, then
replace both stored tokens with the returned pair. Never log tokens or passwords.

The server must register `auth.register`, `auth.login`, `auth.refresh` and
`auth.updateProfile`. The `auth.updateProfile` example assumes the server's
profile schema includes `display_name`. Its fields are sent as strings, matching
the crate's profile API.

OAuth browser redirect/callback handling remains in the host application. Keep
OAuth `state` and PKCE verifier server-side; do not put client secrets in a
mobile application.

## Kotlin Multiplatform-клієнт

Цей спільний Kotlin-модуль викликає JSON-RPC-методи, зареєстровані через
`register_auth_methods`. Приклад охоплює реєстрацію, вхід за паролем,
оновлення токенів і профілю через HTTPS JSON-RPC endpoint застосунку.

### Підключення до KMP-застосунку

З директорії цього прикладу зберіть common та Android source sets командою
`./gradlew :shared:compileCommonMainKotlinMetadata :shared:compileAndroidMain`.
Для Android target потрібен Android SDK; iOS targets збирайте на macOS із
встановленим Xcode.

Додайте модуль `shared` до проєкту й підключіть HTTP engine у platform source
sets. Наприклад, використовуйте `ktor-client-android` у `androidMain` і
`ktor-client-darwin` у `iosMain` тієї самої версії Ktor, що й common-залежності.
Створіть спільний клієнт із platform engine:

```kotlin
// У androidMain:
import io.ktor.client.engine.android.Android

val auth = JsonRpcAuthClient("https://api.example.com/json-rpc", Android.create())

val user = auth.register("reader@example.test", "a long password")
val tokens = auth.login(user.email, "a long password")
val updated = auth.updateProfile(
    accessToken = tokens.access_token,
    profile = mapOf("display_name" to "Reader"),
)
auth.close()
```

Для iOS імпортуйте `io.ktor.client.engine.darwin.Darwin` і передайте
`Darwin.create()` з `iosMain`. У реальному застосунку access
і refresh токени зберігайте у захищеному сховищі платформи (Android Keystore та
iOS Keychain). Для оновлення сесії викличте `refresh(tokens.refresh_token)`,
а потім замініть обидва збережені токени новою парою. Не записуйте токени чи
паролі в логи.

Сервер має зареєструвати `auth.register`, `auth.login`, `auth.refresh` і
`auth.updateProfile`. Приклад `auth.updateProfile` передбачає, що схема профілю
сервера містить `display_name`. Значення надсилаються рядками — так працює API
профілю крейту.

OAuth redirect/callback обробляє застосунок. Зберігайте `state` і PKCE verifier
на сервері; не вбудовуйте client secrets у мобільний застосунок.
