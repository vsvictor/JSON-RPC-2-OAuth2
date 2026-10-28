import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;

class AuthTokens {
  const AuthTokens({
    required this.accessToken,
    required this.refreshToken,
    required this.expiresIn,
  });

  final String accessToken;
  final String refreshToken;
  final int expiresIn;

  factory AuthTokens.fromJson(Map<String, dynamic> json) => AuthTokens(
        accessToken: json['access_token'] as String,
        refreshToken: json['refresh_token'] as String,
        expiresIn: json['expires_in'] as int,
      );
}

class AuthClientException implements Exception {
  const AuthClientException(this.message, {this.rpcCode});

  final String message;
  final int? rpcCode;

  @override
  String toString() => message;
}

class AuthClient {
  AuthClient({
    required this.endpoint,
    http.Client? httpClient,
    FlutterSecureStorage? secureStorage,
  })  : _http = httpClient ?? http.Client(),
        _storage = secureStorage ?? const FlutterSecureStorage();

  final String endpoint;
  final http.Client _http;
  final FlutterSecureStorage _storage;
  int _requestId = 0;

  Future<void> register(String email, String password) async {
    await _call('auth.register', {
      'email': email,
      'password': password,
    });
  }

  Future<AuthTokens> login(String email, String password) async {
    final tokens = AuthTokens.fromJson(
      await _call('auth.login', {
        'email': email,
        'password': password,
        'grant_type': 'password',
      }),
    );
    await _saveTokens(tokens);
    return tokens;
  }

  Future<AuthTokens> refresh() async {
    final refreshToken = await _storage.read(key: 'refresh_token');
    if (refreshToken == null || refreshToken.isEmpty) {
      throw const AuthClientException('No refresh token is stored.');
    }

    final tokens = AuthTokens.fromJson(
      await _call('auth.refresh', {'refresh_token': refreshToken}),
    );
    await _saveTokens(tokens);
    return tokens;
  }

  Future<Map<String, dynamic>> updateProfile(
    Map<String, String> profile,
  ) async {
    final accessToken = await _storage.read(key: 'access_token');
    if (accessToken == null || accessToken.isEmpty) {
      throw const AuthClientException('Sign in before updating the profile.');
    }

    try {
      return await _call('auth.updateProfile', {
        'access_token': accessToken,
        'profile': profile,
      });
    } on AuthClientException catch (error) {
      if (error.rpcCode != -32001) rethrow;
      final tokens = await refresh();
      return _call('auth.updateProfile', {
        'access_token': tokens.accessToken,
        'profile': profile,
      });
    }
  }

  Future<void> logout() async {
    await _storage.delete(key: 'access_token');
    await _storage.delete(key: 'refresh_token');
    await _storage.delete(key: 'email');
  }

  Future<void> _saveTokens(AuthTokens tokens) async {
    await _storage.write(key: 'access_token', value: tokens.accessToken);
    await _storage.write(key: 'refresh_token', value: tokens.refreshToken);
  }

  Future<Map<String, dynamic>> _call(
    String method,
    Map<String, dynamic> params,
  ) async {
    final id = ++_requestId;
    final response = await _http.post(
      Uri.parse(endpoint),
      headers: const {'content-type': 'application/json'},
      body: jsonEncode({
        'jsonrpc': '2.0',
        'method': method,
        'params': params,
        'id': id,
      }),
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw AuthClientException('HTTP ${response.statusCode}');
    }

    final envelope = jsonDecode(response.body) as Map<String, dynamic>;
    if (envelope['id'] != id) {
      throw const AuthClientException('JSON-RPC response id mismatch.');
    }
    final error = envelope['error'];
    if (error != null) {
      final rpcError = error as Map<String, dynamic>;
      throw AuthClientException(
        'JSON-RPC ${rpcError['code']}: ${rpcError['message']}',
        rpcCode: rpcError['code'] as int?,
      );
    }
    final result = envelope['result'];
    if (result is! Map<String, dynamic>) {
      throw const AuthClientException('Invalid JSON-RPC result.');
    }
    return result;
  }

  void close() => _http.close();
}
