import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:json_rpc_2_oauth2_flutter_example/auth_bloc.dart';
import 'package:json_rpc_2_oauth2_flutter_example/auth_client.dart';
import 'package:json_rpc_2_oauth2_flutter_example/main.dart';

void main() {
  testWidgets('renders sign-in and registration actions', (tester) async {
    final client = AuthClient(endpoint: 'https://example.invalid/json-rpc');
    addTearDown(client.close);

    await tester.pumpWidget(
      BlocProvider(
        create: (_) => AuthBloc(client),
        child: const AuthExampleApp(),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Sign in'), findsOneWidget);
    expect(find.text('Register'), findsOneWidget);
  });
}
