/* x4shardnet: minimal non-blocking TLS client for the X4 Shard extension, as a Lua 5.1 C module.
 *
 * X4's Lua cannot open network connections: the UI sandbox has no sockets, ffi.load, io or os. With Protected UI
 * Mode off, package.loadlib can load a Lua C module; the extension loads this one only when the X4 Shard start
 * is played. It links against the game's own lua51_64.dll (LuaJIT 2.1) and system DLLs: ws2_32 (TCP), secur32
 * and crypt32 (TLS by Windows SChannel), bcrypt (keys, signatures, hashes). It does nothing on its own: every call
 * comes from the extension's Lua.
 *
 * The connection is TLS 1.2. A shard has its own self-signed certificate, so the module does not check it against
 * certificate authorities: it reports the certificate's SHA-256 fingerprint, and the extension refuses a shard whose
 * fingerprint is not the one it expects (from the mod, the server list, the invite link or the first visit).
 *
 * Lua API, one connection per process:
 *   net.open(host, port) -> true | nil, err       start a non-blocking connect (host: IP or name)
 *   net.state()          -> "idle" | "connecting" | "connected" [, err]   finishes the connect and the TLS handshake
 *   net.fingerprint()    -> SHA-256 of the shard's certificate as hex, once connected | nil
 *   net.send(str)        -> bytes taken (all of str, or 0 while the outgoing buffer is full) | nil, err
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
#define X4SHARDNET_VERSION "0.12"
#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <security.h>
#include <schannel.h>
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

enum { IDLE, TCP_CONNECTING, TLS_HANDSHAKE, CONNECTED };
static SOCKET sock = INVALID_SOCKET;
static int phase = IDLE;
static int started = 0;
static char rbuf[65536];              /* plaintext for one recv() (and file contents for load()) */
static char host_name[256];           /* the shard's name for SNI */
static CredHandle cred;
static int have_cred = 0;
static CtxtHandle ctx;
static int have_ctx = 0;
static SecPkgContext_StreamSizes sizes;
static unsigned char tin[98304];      /* TLS bytes from the shard, not decrypted yet (a record is up to ~16.5 KB) */
static size_t tin_len = 0;
static unsigned char tout[262144];    /* TLS bytes to the shard, not sent yet */
static size_t tout_len = 0;
static int peer_closed = 0;
static char fp_hex[65];

static void close_sock(void)
{
	if (have_ctx)
		DeleteSecurityContext(&ctx);
	have_ctx = 0;
	if (sock != INVALID_SOCKET)
		closesocket(sock);
	sock = INVALID_SOCKET;
	phase = IDLE;
	tin_len = tout_len = 0;
	peer_closed = 0;
	fp_hex[0] = 0;
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

/* an SChannel status as "tls <what> 0x80090308" */
static int fail_tls(lua_State *L, const char *what, SECURITY_STATUS st)
{
	char msg[96];
	snprintf(msg, sizeof msg, "tls %s 0x%08lx", what, (unsigned long)st);
	close_sock();
	lua_pushnil(L);
	lua_pushstring(L, msg);
	return 2;
}

static int sha256(const unsigned char *data, size_t len, unsigned char out[32])
{
	BCRYPT_ALG_HANDLE alg = NULL;
	BCRYPT_HASH_HANDLE h = NULL;
	int ok = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0 &&
	         BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0) == 0 &&
	         BCryptHashData(h, (PUCHAR)data, (ULONG)len, 0) == 0 &&
	         BCryptFinishHash(h, out, 32, 0) == 0;
	if (h)
		BCryptDestroyHash(h);
	if (alg)
		BCryptCloseAlgorithmProvider(alg, 0);
	return ok;
}

/* Sends what is waiting in tout; 0, or the socket error */
static int flush_out(void)
{
	while (tout_len > 0) {
		int n = send(sock, (const char *)tout, (int)tout_len, 0);
		if (n == SOCKET_ERROR) {
			int err = WSAGetLastError();
			return err == WSAEWOULDBLOCK ? 0 : err;
		}
		memmove(tout, tout + n, tout_len - (size_t)n);
		tout_len -= (size_t)n;
	}
	return 0;
}

/* Reads what the socket has into tin; 0, or the socket error (a closed connection sets peer_closed) */
static int fill_in(void)
{
	while (tin_len < sizeof tin && !peer_closed) {
		int n = recv(sock, (char *)tin + tin_len, (int)(sizeof tin - tin_len), 0);
		if (n > 0) {
			tin_len += (size_t)n;
		} else if (n == 0) {
			peer_closed = 1;
		} else {
			int err = WSAGetLastError();
			return err == WSAEWOULDBLOCK ? 0 : err;
		}
	}
	return 0;
}

static int queue_out(const void *data, size_t len)
{
	if (tout_len + len > sizeof tout)
		return 0;
	memcpy(tout + tout_len, data, len);
	tout_len += len;
	return 1;
}

/* One step of the TLS handshake, with what tin holds (nothing on the first call) */
static SECURITY_STATUS handshake_step(int first)
{
	SecBuffer inb[2], outb[1];
	SecBufferDesc ind, outd;
	DWORD flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
	              ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION;
	DWORD out_flags = 0;
	SECURITY_STATUS st;
	inb[0].BufferType = SECBUFFER_TOKEN;
	inb[0].pvBuffer = tin;
	inb[0].cbBuffer = (unsigned long)tin_len;
	inb[1].BufferType = SECBUFFER_EMPTY;
	inb[1].pvBuffer = NULL;
	inb[1].cbBuffer = 0;
	ind.ulVersion = SECBUFFER_VERSION;
	ind.cBuffers = 2;
	ind.pBuffers = inb;
	outb[0].BufferType = SECBUFFER_TOKEN;
	outb[0].pvBuffer = NULL;
	outb[0].cbBuffer = 0;
	outd.ulVersion = SECBUFFER_VERSION;
	outd.cBuffers = 1;
	outd.pBuffers = outb;
	st = InitializeSecurityContextA(&cred, first ? NULL : &ctx, host_name, flags, 0, 0, first ? NULL : &ind, 0,
	                                &ctx, &outd, &out_flags, NULL);
	if (first && (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_OK))
		have_ctx = 1;
	if (outb[0].pvBuffer) {   /* to the shard: the next handshake message, or an alert on an error */
		if (outb[0].cbBuffer && !queue_out(outb[0].pvBuffer, outb[0].cbBuffer))
			st = SEC_E_BUFFER_TOO_SMALL;
		FreeContextBuffer(outb[0].pvBuffer);
	}
	if (st == SEC_E_INCOMPLETE_MESSAGE || first)
		return st;               /* tin stays as it is: more bytes are needed */
	if (inb[1].BufferType == SECBUFFER_EXTRA && inb[1].cbBuffer > 0 && inb[1].cbBuffer <= tin_len) {
		memmove(tin, tin + tin_len - inb[1].cbBuffer, inb[1].cbBuffer);
		tin_len = inb[1].cbBuffer;
	} else {
		tin_len = 0;
	}
	return st;
}

/* The handshake is done: record sizes and the fingerprint of the shard's certificate */
static SECURITY_STATUS handshake_done(void)
{
	PCCERT_CONTEXT cert = NULL;
	unsigned char hash[32];
	SECURITY_STATUS st = QueryContextAttributesA(&ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
	int i;
	if (st != SEC_E_OK)
		return st;
	st = QueryContextAttributesA(&ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&cert);
	if (st != SEC_E_OK || !cert)
		return st != SEC_E_OK ? st : SEC_E_CERT_UNKNOWN;
	i = sha256(cert->pbCertEncoded, cert->cbCertEncoded, hash);
	CertFreeCertificateContext(cert);
	if (!i)
		return SEC_E_CERT_UNKNOWN;
	for (i = 0; i < 32; i++)
		snprintf(fp_hex + 2 * i, 3, "%02x", hash[i]);
	phase = CONNECTED;
	return SEC_E_OK;
}

static char last_error[96];

/* the handshake failed: close, and keep the reason for state() */
static int handshake_failed(const char *what, long code, int is_tls)
{
	if (is_tls)
		snprintf(last_error, sizeof last_error, "tls %s 0x%08lx", what, (unsigned long)code);
	else if (code)
		snprintf(last_error, sizeof last_error, "%s %ld", what, code);
	else
		snprintf(last_error, sizeof last_error, "%s", what);
	close_sock();
	return -1;
}

/* Drives the handshake with whatever has arrived; 1 when done, 0 while it goes on, -1 failed (last_error) */
static int handshake_pump(void)
{
	int err = fill_in();
	if (err)
		return handshake_failed("recv", err, 0);
	while (phase == TLS_HANDSHAKE && tin_len > 0) {
		SECURITY_STATUS st = handshake_step(0);
		if (st == SEC_E_INCOMPLETE_MESSAGE)
			break;
		if (st == SEC_E_OK) {
			st = handshake_done();
			if (st != SEC_E_OK)
				return handshake_failed("certificate", st, 1);
		} else if (st != SEC_I_CONTINUE_NEEDED) {
			flush_out();   /* the alert, best effort */
			return handshake_failed("handshake", st, 1);
		}
	}
	err = flush_out();
	if (err)
		return handshake_failed("send", err, 0);
	if (phase == TLS_HANDSHAKE && peer_closed)
		return handshake_failed("closed during the TLS handshake", 0, 0);
	return phase == CONNECTED ? 1 : 0;
}

/* The TCP connection is up: start TLS 1.2 (credentials once per process) */
static int handshake_start(void)
{
	SECURITY_STATUS st;
	if (!have_cred) {
		SCHANNEL_CRED sc;
		TimeStamp expiry;
		memset(&sc, 0, sizeof sc);
		sc.dwVersion = SCHANNEL_CRED_VERSION;
		sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
		/* manual validation: the fingerprint is checked by the extension, not by certificate authorities */
		sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
		st = AcquireCredentialsHandleA(NULL, (LPSTR)UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &sc, NULL, NULL,
		                               &cred, &expiry);
		if (st != SEC_E_OK)
			return handshake_failed("credentials", st, 1);
		have_cred = 1;
	}
	st = handshake_step(1);
	if (st != SEC_I_CONTINUE_NEEDED)
		return handshake_failed("hello", st, 1);
	phase = TLS_HANDSHAKE;
	return handshake_pump();
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
	snprintf(host_name, sizeof host_name, "%s", host);
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
	phase = TCP_CONNECTING;
	lua_pushboolean(L, 1);
	return 1;
}

static int l_state(lua_State *L)
{
	if (sock == INVALID_SOCKET) {
		lua_pushstring(L, "idle");
		return 1;
	}
	if (phase == TCP_CONNECTING) {
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
		if (FD_ISSET(sock, &writable) && handshake_start() < 0) {
			lua_pushstring(L, "idle");
			lua_pushstring(L, last_error);
			return 2;
		}
	} else if (phase == TLS_HANDSHAKE && handshake_pump() < 0) {
		lua_pushstring(L, "idle");
		lua_pushstring(L, last_error);
		return 2;
	}
	lua_pushstring(L, phase == CONNECTED ? "connected" : "connecting");
	return 1;
}

static int l_fingerprint(lua_State *L)
{
	if (phase != CONNECTED) {
		lua_pushnil(L);
		return 1;
	}
	lua_pushstring(L, fp_hex);
	return 1;
}

/* Encrypts all of data into tout, record by record; 0 when tout has no room for it */
static int encrypt_all(const char *data, size_t len, SECURITY_STATUS *st)
{
	size_t need = 0, left = len;
	while (left > 0) {   /* room for every record first: then a message never goes out half */
		size_t chunk = left < sizes.cbMaximumMessage ? left : sizes.cbMaximumMessage;
		need += sizes.cbHeader + chunk + sizes.cbTrailer;
		left -= chunk;
	}
	if (tout_len + need > sizeof tout)
		return 0;
	while (len > 0) {
		size_t chunk = len < sizes.cbMaximumMessage ? len : sizes.cbMaximumMessage;
		unsigned char *p = tout + tout_len;
		SecBuffer b[4];
		SecBufferDesc desc;
		memcpy(p + sizes.cbHeader, data, chunk);
		b[0].BufferType = SECBUFFER_STREAM_HEADER;
		b[0].pvBuffer = p;
		b[0].cbBuffer = sizes.cbHeader;
		b[1].BufferType = SECBUFFER_DATA;
		b[1].pvBuffer = p + sizes.cbHeader;
		b[1].cbBuffer = (unsigned long)chunk;
		b[2].BufferType = SECBUFFER_STREAM_TRAILER;
		b[2].pvBuffer = p + sizes.cbHeader + chunk;
		b[2].cbBuffer = sizes.cbTrailer;
		b[3].BufferType = SECBUFFER_EMPTY;
		b[3].pvBuffer = NULL;
		b[3].cbBuffer = 0;
		desc.ulVersion = SECBUFFER_VERSION;
		desc.cBuffers = 4;
		desc.pBuffers = b;
		*st = EncryptMessage(&ctx, 0, &desc, 0);
		if (*st != SEC_E_OK)
			return -1;
		tout_len += b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer;
		data += chunk;
		len -= chunk;
	}
	return 1;
}

static int l_send(lua_State *L)
{
	size_t len;
	const char *data = luaL_checklstring(L, 1, &len);
	SECURITY_STATUS st = SEC_E_OK;
	int err, done;
	if (phase != CONNECTED)
		return fail(L, "not connected", 0);
	err = flush_out();
	if (err) {
		close_sock();
		return fail(L, "send", err);
	}
	done = encrypt_all(data, len, &st);
	if (done < 0)
		return fail_tls(L, "encrypt", st);
	err = flush_out();
	if (err) {
		close_sock();
		return fail(L, "send", err);
	}
	lua_pushinteger(L, done ? (ptrdiff_t)len : 0);
	return 1;
}

static int l_recv(lua_State *L)
{
	size_t out = 0;
	int err;
	if (phase != CONNECTED)
		return fail(L, "not connected", 0);
	err = flush_out();
	if (!err)
		err = fill_in();
	if (err) {
		close_sock();
		return fail(L, "recv", err);
	}
	/* whole records only, and only while rbuf has room for one more */
	while (tin_len > 0 && out + 16384 + 2048 <= sizeof rbuf) {
		SecBuffer b[4];
		SecBufferDesc desc;
		SECURITY_STATUS st;
		int i;
		b[0].BufferType = SECBUFFER_DATA;
		b[0].pvBuffer = tin;
		b[0].cbBuffer = (unsigned long)tin_len;
		for (i = 1; i < 4; i++) {
			b[i].BufferType = SECBUFFER_EMPTY;
			b[i].pvBuffer = NULL;
			b[i].cbBuffer = 0;
		}
		desc.ulVersion = SECBUFFER_VERSION;
		desc.cBuffers = 4;
		desc.pBuffers = b;
		st = DecryptMessage(&ctx, &desc, 0, NULL);
		if (st == SEC_E_INCOMPLETE_MESSAGE)
			break;
		if (st == SEC_I_CONTEXT_EXPIRED) {   /* the shard said close_notify */
			tin_len = 0;
			peer_closed = 1;
			break;
		}
		if (st != SEC_E_OK)
			return fail_tls(L, st == SEC_I_RENEGOTIATE ? "renegotiation" : "decrypt", st);
		for (i = 0; i < 4; i++)
			if (b[i].BufferType == SECBUFFER_DATA && b[i].cbBuffer && out + b[i].cbBuffer <= sizeof rbuf) {
				memcpy(rbuf + out, b[i].pvBuffer, b[i].cbBuffer);
				out += b[i].cbBuffer;
			}
		for (i = 0; i < 4 && b[i].BufferType != SECBUFFER_EXTRA; i++)
			;
		if (i < 4 && b[i].cbBuffer > 0 && b[i].cbBuffer <= tin_len) {
			memmove(tin, tin + tin_len - b[i].cbBuffer, b[i].cbBuffer);
			tin_len = b[i].cbBuffer;
		} else {
			tin_len = 0;
		}
	}
	if (out > 0) {   /* what came before a close still goes out first */
		lua_pushlstring(L, rbuf, out);
		return 1;
	}
	if (peer_closed && tin_len == 0) {
		close_sock();
		return fail(L, "closed", 0);
	}
	lua_pushlstring(L, "", 0);
	return 1;
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
	{ "fingerprint", l_fingerprint },
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
	lua_createtable(L, 0, 12);   /* the entries of funcs */
	luaL_register(L, NULL, funcs);
	return 1;
}
