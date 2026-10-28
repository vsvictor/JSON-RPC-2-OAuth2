import 'package:flutter_bloc/flutter_bloc.dart';

import 'auth_client.dart';

sealed class AuthEvent {
  const AuthEvent();
}

final class RegisterRequested extends AuthEvent {
  const RegisterRequested(this.email, this.password);
  final String email;
  final String password;
}

final class LoginRequested extends AuthEvent {
  const LoginRequested(this.email, this.password);
  final String email;
  final String password;
}

final class ProfileUpdateRequested extends AuthEvent {
  const ProfileUpdateRequested(this.displayName);
  final String displayName;
}

final class LogoutRequested extends AuthEvent {
  const LogoutRequested();
}

sealed class AuthState {
  const AuthState();
}

final class AuthSignedOut extends AuthState {
  const AuthSignedOut({this.message});
  final String? message;
}

final class AuthLoading extends AuthState {
  const AuthLoading();
}

final class AuthSignedIn extends AuthState {
  const AuthSignedIn(this.email, {this.message});
  final String email;
  final String? message;
}

class AuthBloc extends Bloc<AuthEvent, AuthState> {
  AuthBloc(this._client) : super(const AuthSignedOut()) {
    on<RegisterRequested>(_register);
    on<LoginRequested>(_login);
    on<ProfileUpdateRequested>(_updateProfile);
    on<LogoutRequested>(_logout);
  }

  final AuthClient _client;

  Future<void> _register(
    RegisterRequested event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthLoading());
    try {
      await _client.register(event.email, event.password);
      final tokens = await _client.login(event.email, event.password);
      emit(AuthSignedIn(event.email,
          message: 'Account created. Token expires in ${tokens.expiresIn}s.'));
    } catch (error) {
      emit(AuthSignedOut(message: error.toString()));
    }
  }

  Future<void> _login(
    LoginRequested event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthLoading());
    try {
      await _client.login(event.email, event.password);
      emit(AuthSignedIn(event.email));
    } catch (error) {
      emit(AuthSignedOut(message: error.toString()));
    }
  }

  Future<void> _updateProfile(
    ProfileUpdateRequested event,
    Emitter<AuthState> emit,
  ) async {
    final current = state;
    if (current is! AuthSignedIn) return;
    emit(const AuthLoading());
    try {
      await _client.updateProfile({'display_name': event.displayName});
      emit(AuthSignedIn(current.email, message: 'Profile updated.'));
    } catch (error) {
      emit(AuthSignedIn(current.email, message: error.toString()));
    }
  }

  Future<void> _logout(
    LogoutRequested event,
    Emitter<AuthState> emit,
  ) async {
    try {
      await _client.logout();
      emit(const AuthSignedOut());
    } catch (error) {
      emit(AuthSignedOut(message: error.toString()));
    }
  }
}
