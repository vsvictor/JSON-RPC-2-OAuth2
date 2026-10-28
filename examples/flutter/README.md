# Flutter client example

This Flutter app calls the `auth.register`, `auth.login`, `auth.refresh`, and
`auth.updateProfile` JSON-RPC methods. Authentication state is managed with
`flutter_bloc`; both tokens are stored using `flutter_secure_storage`.

## Run

1. Configure the Rust server to register the auth methods and define a
   `display_name` profile field.
2. Set an HTTPS JSON-RPC URL and launch:

   ```sh
   flutter pub get
   flutter run --dart-define=AUTH_RPC_URL=https://api.example.com/json-rpc
   ```

3. Use **Register** for a new account or **Sign in** for an existing one.
   After login, update the profile from the authenticated screen.

Use the emulator/device's reachable API address. For a local Android emulator,
the host machine is usually reachable at `10.0.2.2`; physical devices need a
reachable LAN address or a deployed HTTPS endpoint. Do not send passwords or
tokens over untrusted cleartext connections in production.

OAuth browser redirect/callback handling must be implemented by the host
application and server. Never embed provider client secrets in the Flutter app.

## Flutter-клієнт

Цей Flutter-застосунок викликає JSON-RPC-методи `auth.register`, `auth.login`,
`auth.refresh` і `auth.updateProfile`. Стан автентифікації керується через
`flutter_bloc`, а обидва токени зберігаються у `flutter_secure_storage`.

### Запуск

1. Налаштуйте Rust-сервер: зареєструйте auth-методи та додайте поле
   `display_name` до схеми профілю.
2. Задайте HTTPS URL JSON-RPC та запустіть застосунок:

   ```sh
   flutter pub get
   flutter run --dart-define=AUTH_RPC_URL=https://api.example.com/json-rpc
   ```

3. Для нового акаунта натисніть **Register**, для наявного — **Sign in**.
   Після входу можна оновити профіль на екрані автентифікованого користувача.

Використовуйте адресу API, доступну з емулятора чи пристрою. Для локального
Android-емулятора хост зазвичай доступний через `10.0.2.2`; фізичному пристрою
потрібна доступна LAN-адреса або розгорнутий HTTPS endpoint. У production не
передавайте паролі чи токени незахищеним з'єднанням.

OAuth browser redirect/callback мають оброблятися застосунком і сервером. Не
вбудовуйте client secrets провайдера у Flutter-застосунок.
