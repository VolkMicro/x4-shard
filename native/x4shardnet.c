/* x4shardnet: minimal non-blocking TCP client for the X4 Shard extension, as a Lua 5.1 C module.
 *
 * X4's Lua cannot open network connections: the UI sandbox has no sockets, ffi.load, io or os. With Protected UI
 * Mode off, package.loadlib can load a Lua C module; the extension loads this one only when the X4 Shard start
 * is played. It links against the game's own lua51_64.dll (LuaJIT 2.1) and two system DLLs, ws2_32 (TCP) and
 * bcrypt (keys and signatures). It does nothing on its own: every call comes from the extension's Lua.
 *
 * Lua API, one connection per process:
 *   net.open(host, port) -> true | nil, err       start a non-blocking connect (host: IP or name)
 *   net.state()          -> "idle" | "connecting" | "connected" [, err]   finishes the connect when it is ready
 *   net.send(str)        -> bytes sent (0 when the socket buffer is full) | nil, err
 *   net.recv()           -> data ("" when nothing is waiting) | nil, err  ("closed": the server closed)
 *   net.close()
 *   net.keygen()         -> new ECDSA P-256 private key (BCrypt blob) as hex: the player's identity
 *   net.sign(key, msg)   -> ECDSA signature over SHA-256(msg), r and s as hex | nil, err
 *   net.persona()        -> the player's own Steam nickname, from the steam_api64.dll the game has loaded
 *   net.load(name)       -> contents of %LOCALAPPDATA%\X4Shard\<name> | nil, err
 *   net.save(name, data) -> true | nil, err    (name: letters, digits, '.', '_', '-'; written via a temp file)
 *   net.version()        -> this module's version
 *
 * Build: native/build.sh (MinGW-w64; no timestamp in the PE header, so the same source gives the same DLL)
 */
#define X4SHARDNET_VERSION "0.11"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <stdio.h>

typedef struct lua_State lua_State;
typedef int (*lua_CFunction)(lua_State *L);
typedef struct luaL_Reg { const char *name; lua_CFunction func; } luaL_Reg;

/* Lua 5.1 API exported by lua51_64.dll (import library from lua51_64.def) */
__declspec(dllimport) void lua_pushnil(lua_State *L);
__declspec(dllimport) void lua_pushboolean(lua_State *L, int b);
__declspec(dllimport) void lua_pushinteger(lua_State *L, ptrdiff_t n);
__declspec(dllimport) void lua_pushstring(lua_State *L, const char *s);
__declspec(dllimport) void lua_pushlstring(lua_State *L, const char *s, size_t len);
__declspec(dllimport) void lua_createtable(lua_State *L, int narr, int nrec);
__declspec(dllimport) const char *luaL_checklstring(lua_State *L, int narg, size_t *len);
__declspec(dllimport) ptrdiff_t luaL_checkinteger(lua_State *L, int narg);
__declspec(dllimport) void luaL_register(lua_State *L, const char *libname, const luaL_Reg *l);

static SOCKET sock = INVALID_SOCKET;
static int connecting = 0;
static int started = 0;
static char rbuf[65536];

static void close_sock(void)
{
	if (sock != INVALID_SOCKET)
		closesocket(sock);
	sock = INVALID_SOCKET;
	connecting = 0;
}

static int fail(lua_State *L, const char *what, int code)
{
	char msg[96];
	if (code)
		snprintf(msg, sizeof msg, "%s %d", what, code);
	else
		snprintf(msg, sizeof msg, "%s", what);
	lua_pushnil(L);
	lua_pushstring(L, msg);
	return 2;
}

static int l_open(lua_State *L)
{
	const char *host = luaL_checklstring(L, 1, NULL);
	int port = (int)luaL_checkinteger(L, 2);
	char service[16];
	struct addrinfo hints, *res = NULL;
	u_long nonblocking = 1;
	BOOL nodelay = TRUE;
	int rc;

	if (!started) {
		WSADATA data;
		if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
			return fail(L, "WSAStartup", WSAGetLastError());
		started = 1;
	}
	close_sock();
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	snprintf(service, sizeof service, "%d", port);
	if (getaddrinfo(host, service, &hints, &res) != 0 || !res)
		return fail(L, "resolve", WSAGetLastError());
	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock == INVALID_SOCKET) {
		freeaddrinfo(res);
		return fail(L, "socket", WSAGetLastError());
	}
	ioctlsocket(sock, FIONBIO, &nonblocking);
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof nodelay);
	rc = connect(sock, res->ai_addr, (int)res->ai_addrlen);
	freeaddrinfo(res);
	if (rc == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
		int err = WSAGetLastError();
		close_sock();
		return fail(L, "connect", err);
	}
	connecting = 1;
	lua_pushboolean(L, 1);
	return 1;
}

static int l_state(lua_State *L)
{
	if (sock == INVALID_SOCKET) {
		lua_pushstring(L, "idle");
		return 1;
	}
	if (connecting) {
		fd_set writable, failed;
		struct timeval now = { 0, 0 };
		FD_ZERO(&writable);
		FD_ZERO(&failed);
		FD_SET(sock, &writable);
		FD_SET(sock, &failed);
		if (select(0, NULL, &writable, &failed, &now) == SOCKET_ERROR) {
			int err = WSAGetLastError();
			char msg[48];
			close_sock();
			snprintf(msg, sizeof msg, "select %d", err);
			lua_pushstring(L, "idle");
			lua_pushstring(L, msg);
			return 2;
		}
		if (FD_ISSET(sock, &failed)) {
			int err = 0, len = sizeof err;
			char msg[48];
			getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
			close_sock();
			snprintf(msg, sizeof msg, "connect failed %d", err);
			lua_pushstring(L, "idle");
			lua_pushstring(L, msg);
			return 2;
		}
		if (FD_ISSET(sock, &writable))
			connecting = 0;
	}
	lua_pushstring(L, connecting ? "connecting" : "connected");
	return 1;
}

static int l_send(lua_State *L)
{
	size_t len;
	const char *data = luaL_checklstring(L, 1, &len);
	int n;
	if (sock == INVALID_SOCKET || connecting)
		return fail(L, "not connected", 0);
	n = send(sock, data, (int)len, 0);
	if (n == SOCKET_ERROR) {
		int err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK) {
			lua_pushinteger(L, 0);
			return 1;
		}
		close_sock();
		return fail(L, "send", err);
	}
	lua_pushinteger(L, n);
	return 1;
}

static int l_recv(lua_State *L)
{
	int n;
	if (sock == INVALID_SOCKET || connecting)
		return fail(L, "not connected", 0);
	n = recv(sock, rbuf, (int)sizeof rbuf, 0);
	if (n > 0) {
		lua_pushlstring(L, rbuf, (size_t)n);
		return 1;
	}
	if (n == 0) {
		close_sock();
		return fail(L, "closed", 0);
	}
	if (WSAGetLastError() == WSAEWOULDBLOCK) {
		lua_pushlstring(L, "", 0);
		return 1;
	}
	{
		int err = WSAGetLastError();
		close_sock();
		return fail(L, "recv", err);
	}
}

static int l_close(lua_State *L)
{
	(void)L;
	close_sock();
	return 0;
}

/* The player's identity: an ECDSA P-256 key pair. The private key never leaves the PC; a shard gets the public key
 * and, at each login, a signature over its own random challenge, so nothing that crosses the network (or that a
 * shard learns) logs the player in again, whatever address the shard was reached at. */
#define KEY_BLOB (sizeof(BCRYPT_ECCKEY_BLOB) + 3 * 32)   /* BCRYPT_ECCPRIVATE_BLOB: header, X, Y, d */

static void push_hex(lua_State *L, const unsigned char *bytes, size_t n)
{
	char hex[2 * KEY_BLOB + 1];
	size_t i;
	for (i = 0; i < n && i < KEY_BLOB; i++)
		snprintf(hex + 2 * i, 3, "%02x", bytes[i]);
	lua_pushlstring(L, hex, 2 * i);
}

static int nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static size_t from_hex(const char *hex, size_t len, unsigned char *out, size_t size)
{
	size_t i;
	if (len % 2 || len / 2 > size)
		return 0;
	for (i = 0; i < len / 2; i++) {
		int hi = nibble(hex[2 * i]), lo = nibble(hex[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return 0;
		out[i] = (unsigned char)(hi * 16 + lo);
	}
	return len / 2;
}

/* net.keygen() -> private key blob as hex (the public key is its bytes 8..71: X and Y) */
static int l_keygen(lua_State *L)
{
	BCRYPT_ALG_HANDLE alg = NULL;
	BCRYPT_KEY_HANDLE key = NULL;
	unsigned char blob[KEY_BLOB];
	ULONG len = 0;
	int ok = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0) == 0 &&
	         BCryptGenerateKeyPair(alg, &key, 256, 0) == 0 &&
	         BCryptFinalizeKeyPair(key, 0) == 0 &&
	         BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, blob, sizeof blob, &len, 0) == 0;
	if (key)
		BCryptDestroyKey(key);
	if (alg)
		BCryptCloseAlgorithmProvider(alg, 0);
	if (!ok || len != sizeof blob)
		return fail(L, "keygen", 0);
	push_hex(L, blob, len);
	SecureZeroMemory(blob, sizeof blob);
	return 1;
}

/* net.sign(private key hex, message) -> ECDSA signature over SHA-256(message): r and s, 64 bytes as hex */
static int l_sign(lua_State *L)
{
	size_t klen, mlen;
	const char *keyhex = luaL_checklstring(L, 1, &klen);
	const char *msg = luaL_checklstring(L, 2, &mlen);
	unsigned char blob[KEY_BLOB], hash[32], sig[64];
	BCRYPT_ALG_HANDLE alg = NULL, sha = NULL;
	BCRYPT_KEY_HANDLE key = NULL;
	BCRYPT_HASH_HANDLE h = NULL;
	ULONG len = 0;
	int ok = from_hex(keyhex, klen, blob, sizeof blob) == sizeof blob &&
	         BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0 &&
	         BCryptCreateHash(sha, &h, NULL, 0, NULL, 0, 0) == 0 &&
	         BCryptHashData(h, (PUCHAR)msg, (ULONG)mlen, 0) == 0 &&
	         BCryptFinishHash(h, hash, sizeof hash, 0) == 0 &&
	         BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0) == 0 &&
	         BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPRIVATE_BLOB, &key, blob, sizeof blob, 0) == 0 &&
	         BCryptSignHash(key, NULL, hash, sizeof hash, sig, sizeof sig, &len, 0) == 0 && len == sizeof sig;
	SecureZeroMemory(blob, sizeof blob);
	if (h)
		BCryptDestroyHash(h);
	if (key)
		BCryptDestroyKey(key);
	if (sha)
		BCryptCloseAlgorithmProvider(sha, 0);
	if (alg)
		BCryptCloseAlgorithmProvider(alg, 0);
	if (!ok)
		return fail(L, "sign", 0);
	push_hex(L, sig, sizeof sig);
	return 1;
}

static int l_version(lua_State *L)
{
	lua_pushstring(L, X4SHARDNET_VERSION);
	return 1;
}

/* Steamworks flat API of the steam_api64.dll that X4 ships (accessor version as exported by it) */
static int l_persona(lua_State *L)
{
	typedef void *(*friends_fn)(void);
	typedef const char *(*persona_fn)(void *);
	HMODULE steam = GetModuleHandleA("steam_api64.dll");
	friends_fn friends = steam ? (friends_fn)(void *)GetProcAddress(steam, "SteamAPI_SteamFriends_v017") : NULL;
	persona_fn persona = steam ? (persona_fn)(void *)GetProcAddress(steam, "SteamAPI_ISteamFriends_GetPersonaName") : NULL;
	void *iface = friends ? friends() : NULL;
	const char *name = (iface && persona) ? persona(iface) : NULL;
	if (!name || !*name)
		return fail(L, steam ? "no persona" : "no steam_api64", 0);
	lua_pushstring(L, name);
	return 1;
}

/* %LOCALAPPDATA%\X4Shard\<name>, only plain file names: the module never writes anywhere else */
static int data_path(const char *name, char *path, size_t size)
{
	char base[MAX_PATH];
	const char *c;
	DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, sizeof base);
	if (n == 0 || n >= sizeof base || !*name || strlen(name) > 64)
		return 0;
	for (c = name; *c; c++)
		if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9') ||
		      *c == '.' || *c == '_' || *c == '-'))
			return 0;
	if (name[0] == '.')
		return 0;
	snprintf(path, size, "%s\\X4Shard", base);
	CreateDirectoryA(path, NULL);
	snprintf(path, size, "%s\\X4Shard\\%s", base, name);
	return 1;
}

static int l_load(lua_State *L)
{
	char path[MAX_PATH + 80];
	FILE *f;
	size_t n;
	if (!data_path(luaL_checklstring(L, 1, NULL), path, sizeof path))
		return fail(L, "bad name", 0);
	f = fopen(path, "rb");
	if (!f)
		return fail(L, "missing", 0);
	n = fread(rbuf, 1, sizeof rbuf, f);
	fclose(f);
	lua_pushlstring(L, rbuf, n);
	return 1;
}

static int l_save(lua_State *L)
{
	char path[MAX_PATH + 80], tmp[MAX_PATH + 90];
	size_t len;
	const char *data;
	FILE *f;
	if (!data_path(luaL_checklstring(L, 1, NULL), path, sizeof path))
		return fail(L, "bad name", 0);
	data = luaL_checklstring(L, 2, &len);
	snprintf(tmp, sizeof tmp, "%s.tmp", path);
	f = fopen(tmp, "wb");
	if (!f)
		return fail(L, "cannot write", (int)GetLastError());
	if (fwrite(data, 1, len, f) != len) {
		fclose(f);
		return fail(L, "short write", 0);
	}
	fclose(f);
	if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		return fail(L, "cannot replace", (int)GetLastError());
	lua_pushboolean(L, 1);
	return 1;
}

static const luaL_Reg funcs[] = {
	{ "open", l_open },
	{ "state", l_state },
	{ "send", l_send },
	{ "recv", l_recv },
	{ "close", l_close },
	{ "keygen", l_keygen },
	{ "sign", l_sign },
	{ "version", l_version },
	{ "persona", l_persona },
	{ "load", l_load },
	{ "save", l_save },
	{ NULL, NULL },
};

__declspec(dllexport) int luaopen_x4shardnet(lua_State *L)
{
	lua_createtable(L, 0, 11);   /* the entries of funcs */
	luaL_register(L, NULL, funcs);
	return 1;
}
