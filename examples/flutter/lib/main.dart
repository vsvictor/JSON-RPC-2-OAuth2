import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';

import 'auth_bloc.dart';
import 'auth_client.dart';

const _rpcEndpoint = String.fromEnvironment(
  'AUTH_RPC_URL',
  defaultValue: 'https://example.invalid/json-rpc',
);

void main() {
  runApp(
    RepositoryProvider(
      create: (_) => AuthClient(endpoint: _rpcEndpoint),
      dispose: (client) => client.close(),
      child: Builder(
        builder: (context) => BlocProvider(
          create: (_) => AuthBloc(context.read<AuthClient>()),
          child: const AuthExampleApp(),
        ),
      ),
    ),
  );
}

class AuthExampleApp extends StatelessWidget {
  const AuthExampleApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'JSON-RPC OAuth2 example',
        theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
        home: const AuthPage(),
      );
}

class AuthPage extends StatefulWidget {
  const AuthPage({super.key});

  @override
  State<AuthPage> createState() => _AuthPageState();
}

class _AuthPageState extends State<AuthPage> {
  final _email = TextEditingController();
  final _password = TextEditingController();
  final _displayName = TextEditingController();

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    _displayName.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('JSON-RPC OAuth2')),
        body: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: BlocBuilder<AuthBloc, AuthState>(
                builder: (context, state) {
                  if (state is AuthLoading) {
                    return const CircularProgressIndicator();
                  }
                  if (state is AuthSignedIn) {
                    return _signedIn(context, state);
                  }
                  return _signedOut(context, state as AuthSignedOut);
                },
              ),
            ),
          ),
        ),
      );

  Widget _signedOut(BuildContext context, AuthSignedOut state) => Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: _email,
            keyboardType: TextInputType.emailAddress,
            decoration: const InputDecoration(labelText: 'Email'),
          ),
          TextField(
            controller: _password,
            obscureText: true,
            decoration: const InputDecoration(labelText: 'Password'),
          ),
          if (state.message case final message?)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(message, style: const TextStyle(color: Colors.red)),
            ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 12,
            children: [
              FilledButton(
                onPressed: () => context.read<AuthBloc>().add(
                      LoginRequested(_email.text, _password.text),
                    ),
                child: const Text('Sign in'),
              ),
              OutlinedButton(
                onPressed: () => context.read<AuthBloc>().add(
                      RegisterRequested(_email.text, _password.text),
                    ),
                child: const Text('Register'),
              ),
            ],
          ),
        ],
      );

  Widget _signedIn(BuildContext context, AuthSignedIn state) => Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text('Signed in as ${state.email}'),
          TextField(
            controller: _displayName,
            decoration: const InputDecoration(labelText: 'Display name'),
          ),
          if (state.message case final message?)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(message),
            ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 12,
            children: [
              FilledButton(
                onPressed: () => context.read<AuthBloc>().add(
                      ProfileUpdateRequested(_displayName.text),
                    ),
                child: const Text('Update profile'),
              ),
              TextButton(
                onPressed: () =>
                    context.read<AuthBloc>().add(const LogoutRequested()),
                child: const Text('Sign out'),
              ),
            ],
          ),
        ],
      );
}
