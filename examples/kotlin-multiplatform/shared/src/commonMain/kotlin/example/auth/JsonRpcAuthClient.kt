package example.auth

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.plugins.expectSuccess
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

@Serializable
data class TokenResponse(
    val access_token: String,
    val refresh_token: String,
    val token_type: String,
    val expires_in: Long,
)

@Serializable
data class UserResponse(
    val id: String,
    val email: String,
    val created_at: String,
    val roles: List<String> = emptyList(),
    val profile: JsonObject = JsonObject(emptyMap()),
)

@Serializable
private data class RpcRequest(
    val jsonrpc: String = "2.0",
    val method: String,
    val params: JsonObject,
    val id: Long,
)

@Serializable
private data class RpcResponse<T>(
    val jsonrpc: String,
    val id: Long,
    val result: T? = null,
    val error: RpcError? = null,
)

@Serializable
private data class RpcError(
    val code: Int,
    val message: String,
)

class JsonRpcAuthClient(
    private val endpoint: String,
    engine: HttpClientEngine,
) {
    private val httpClient = HttpClient(engine) {
        expectSuccess = true
        install(ContentNegotiation) {
            json(Json {
                ignoreUnknownKeys = true
                explicitNulls = false
            })
        }
    }
    private val requestIdMutex = Mutex()
    private var nextRequestId = 0L

    suspend fun register(email: String, password: String): UserResponse =
        call(
            method = "auth.register",
            params = buildJsonObject {
                put("email", email)
                put("password", password)
            },
        )

    suspend fun login(email: String, password: String): TokenResponse =
        call(
            method = "auth.login",
            params = buildJsonObject {
                put("email", email)
                put("password", password)
                put("grant_type", "password")
            },
        )

    suspend fun refresh(refreshToken: String): TokenResponse =
        call(
            method = "auth.refresh",
            params = buildJsonObject { put("refresh_token", refreshToken) },
        )

    suspend fun updateProfile(
        accessToken: String,
        profile: Map<String, String>,
    ): UserResponse =
        call(
            method = "auth.updateProfile",
            params = buildJsonObject {
                put("access_token", accessToken)
                put(
                    "profile",
                    JsonObject(profile.mapValues { kotlinx.serialization.json.JsonPrimitive(it.value) }),
                )
            },
        )

    private suspend inline fun <reified T> call(
        method: String,
        params: JsonObject,
    ): T {
        val id = requestIdMutex.withLock { ++nextRequestId }
        val response = httpClient.post(endpoint) {
            contentType(ContentType.Application.Json)
            setBody(RpcRequest(method = method, params = params, id = id))
        }
        val rpc = response.body<RpcResponse<T>>()

        if (rpc.id != id) {
            throw SerializationException("JSON-RPC response id did not match the request")
        }
        rpc.error?.let { throw JsonRpcException(it.code, it.message) }
        return rpc.result ?: throw SerializationException("JSON-RPC response has no result")
    }

    fun close() = httpClient.close()
}

class JsonRpcException(
    val code: Int,
    override val message: String,
) : Exception("JSON-RPC error $code: $message")
