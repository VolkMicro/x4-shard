"""The extension's client (ui/x4shard_net.lua) outside the game, on Windows: the game's own lua51_64.dll runs it with
the real network module and stand-ins for the game's API, against local shards over TLS.

Scenarios, each in a fresh Lua state:
  A  the directory shows its pinned certificate: list, pick, login; the shard is remembered with its fingerprint
  B  the directory shows another certificate: not used, the shards joined before are offered
  C  an address with a wrong #fingerprint: refused
  D  a bare address, first visit: joined and remembered; the shard comes back with a new certificate: refused

usage: python -I tools/clienttest.py <x4shardnet_64.dll> [X4 folder, default D:\\SteamLibrary\\steamapps\\common\\X4 Foundations]
%LOCALAPPDATA% points to a temporary folder for the run: the player's own X4Shard folder is not touched.
"""
import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT, PORT2 = 47191, 47192

MOCK = r"""
events, handlers, clock = {}, {}, 0
function getElapsedTime() return clock end
function DebugError(text) print("  log: " .. text) end
function GetExtensionList() return { { name = "X4 Shard", enabled = true, isworkshop = false, location = "x4shard" } } end
function GetUISafeModeOption() return false end
function AddUITriggeredEvent(_, kind, args)
  events[#events + 1] = { kind, args }
  if kind == "notify" then print("  NOTIFY " .. tostring(args[1]))
  elseif kind == "servers" then print("  SERVERS " .. table.concat(args, " / ")) end
end
function RegisterEvent(name, fn) handlers[name] = fn end
function GetComponentData() return "cluster_13_sector001_macro" end
function ConvertStringTo64Bit(s) return tonumber(s) or 0 end
function ConvertStringToLuaID(s) return s end
X4ShardMenu = { open = function (text) print("  address window opened") end }
X4MockC = {
  GetPlayerControlledShipID = function () return 0 end,
  GetContextByClass = function () return 0 end,
  GetSteamID = function () return "" end,
  GetPlayerName = function () return "MockPilot" end,
}
local ffi = require("ffi")
pcall(ffi.cdef, "void Sleep(unsigned long ms);")
function run(seconds, done)
  for _ = 1, seconds * 20 do
    clock = clock + 0.05
    handlers["x4shard.tick"]()
    if done and done() then return true end
    ffi.C.Sleep(15)
  end
  return false
end
function notified(pattern)
  for _, e in ipairs(events) do
    if e[1] == "notify" and tostring(e[2][1]):find(pattern) then return true end
  end
  return false
end
function lastServers()
  for i = #events, 1, -1 do
    if events[i][1] == "servers" then return events[i][2] end
  end
end
"""

SCENARIO = {
    "A": r"""
assert(run(10, lastServers), "no server list")
local labels = lastServers()
assert(labels[1]:find("^Test Dir"), "the directory's shard first: " .. table.concat(labels, ", "))
handlers["x4shard.pick"](nil, "x4shard_srv_1")
assert(run(10, function () return notified("connected to Test Dir") end), "not connected")
""",
    "B": r"""
assert(run(10, function () return notified("did not show its known certificate") end), "a wrong directory was used")
assert(run(5, lastServers), "no list after the refusal")
local labels = table.concat(lastServers(), ", ")
assert(labels:find("Test Dir") and labels:find("Connect by address"), "joined before and by address: " .. labels)
""",
    "C": r"""
assert(run(10, lastServers), "no server list")
X4Shard.joinAddress("x4shard://127.0.0.1:%d#" .. string.rep("1", 64))
assert(run(10, function () return notified("another certificate than expected") end), "a wrong #fingerprint was accepted")
""" % PORT,
    "D1": r"""
assert(run(10, lastServers), "no server list")
X4Shard.joinAddress("127.0.0.1:%d")
assert(run(10, function () return notified("connected to Test Other") end), "first visit failed")
""" % PORT2,
    "D2": r"""
assert(run(10, lastServers), "no server list")
X4Shard.joinAddress("127.0.0.1:%d")
assert(run(10, function () return notified("another certificate than expected") end), "a new certificate was accepted")
""" % PORT2,
}


def lua_api(game):
    os.add_dll_directory(game)
    lua = ctypes.CDLL(os.path.join(game, "lua51_64.dll"))
    lua.luaL_newstate.restype = ctypes.c_void_p
    lua.luaL_openlibs.argtypes = [ctypes.c_void_p]
    lua.luaL_loadbuffer.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lua.lua_pcall.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    lua.lua_tolstring.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    lua.lua_tolstring.restype = ctypes.c_char_p
    return lua


def run_lua(lua, chunks):
    state = lua.luaL_newstate()
    lua.luaL_openlibs(state)
    for name, code in chunks:
        raw = code.encode()
        if lua.luaL_loadbuffer(state, raw, len(raw), ("@" + name).encode()) or lua.lua_pcall(state, 0, 0, 0):
            print("  LUA ERROR in %s: %s" % (name, lua.lua_tolstring(state, -1, None).decode(errors="replace")))
            return False
    return True


def shard(tmp, port, name, accounts, directory=False):
    args = [sys.executable, "-I", os.path.join(ROOT, "server", "shard_server.py"), "--host", "127.0.0.1", "--port",
            str(port), "--name", name, "--accounts", os.path.join(tmp, accounts)] + (["--directory"] if directory else [])
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    dll = os.path.abspath(sys.argv[1])
    game = sys.argv[2] if len(sys.argv) > 2 else r"D:\SteamLibrary\steamapps\common\X4 Foundations"
    tmp = tempfile.mkdtemp()
    os.environ["LOCALAPPDATA"] = os.path.join(tmp, "localappdata")   # the module keeps its files there
    os.makedirs(os.environ["LOCALAPPDATA"])
    os.makedirs(os.path.join(tmp, "extensions", "x4shard", "native"))
    shutil.copy(dll, os.path.join(tmp, "extensions", "x4shard", "native", "x4shardnet_64.dll"))
    os.chdir(tmp)   # the extension's paths start at the game folder
    source = open(os.path.join(ROOT, "extension", "x4shard", "ui", "x4shard_net.lua"), encoding="utf-8").read()
    client = source.replace("local C = ffi.C\n", "local C = X4MockC or ffi.C\n", 1)
    assert client != source, "the client no longer has 'local C = ffi.C'"
    sys.path.insert(0, os.path.join(ROOT, "server"))
    import tlscert
    pin = tlscert.load_or_make(os.path.join(tmp, "dir.json"))[2]
    lua = lua_api(game)
    procs = [shard(tmp, PORT, "Test Dir", "dir.json", directory=True), shard(tmp, PORT2, "Test Other", "other.json")]
    time.sleep(1.5)
    results = {}
    try:
        for key, fp in (("A", pin), ("B", "0" * 64), ("C", pin), ("D1", pin), ("D2", pin)):
            if key == "D2":   # the second shard reinstalled: a new certificate at the same address
                procs[1].terminate()
                procs[1].wait(5)
                for ext in (".cert.pem", ".key.pem"):
                    os.remove(os.path.join(tmp, "other.json" + ext))
                procs[1] = shard(tmp, PORT2, "Test Other", "other.json")
                time.sleep(1.5)
            print("scenario %s" % key, flush=True)
            config = 'X4ShardConfig = { host = "127.0.0.1", port = %d, fingerprint = "%s" }' % (PORT, fp)
            results[key] = run_lua(lua, [("mock", MOCK), ("config", config), ("x4shard_net.lua", client),
                                         ("scenario " + key, SCENARIO[key])])
            print("scenario %s: %s" % (key, "ok" if results[key] else "FAILED"), flush=True)
        saved = open(os.path.join(os.environ["LOCALAPPDATA"], "X4Shard", "servers.txt"), encoding="utf-8").read()
        print("servers.txt:\n" + saved)
        assert pin in saved, "the directory's shard must be remembered with its fingerprint"
    finally:
        for proc in procs:
            proc.terminate()
    print("CLIENTTEST %s" % ("OK" if all(results.values()) else "FAILED"))
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
