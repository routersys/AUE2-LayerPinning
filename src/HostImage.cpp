#include "HostImage.h"

#include <windows.h>
#include <bcrypt.h>
#include <string.h>

namespace lp {

static unsigned char* g_base = nullptr;
static size_t g_size = 0;

static void Resolve() {
    if (g_base) return;
    g_base = (unsigned char*)GetModuleHandleW(nullptr);
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)g_base;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(g_base + dos->e_lfanew);
    g_size = nt->OptionalHeader.SizeOfImage;
}

unsigned char* ImageBase() { Resolve(); return g_base; }
size_t ImageSize() { Resolve(); return g_size; }

bool ImageBytesMatch(unsigned long rva, const unsigned char* bytes, size_t len) {
    Resolve();
    if (!g_base || (size_t)rva + len > g_size) return false;
    return memcmp(g_base + rva, bytes, len) == 0;
}

static bool HashHostFile(unsigned long long* size, unsigned char* out) {
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    bool ok = false;
    LARGE_INTEGER fileSize = {};
    if (GetFileSizeEx(file, &fileSize)) {
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
            if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
                static unsigned char buf[1 << 16];
                ok = true;
                for (;;) {
                    DWORD got = 0;
                    if (!ReadFile(file, buf, sizeof(buf), &got, nullptr)) { ok = false; break; }
                    if (!got) break;
                    if (BCryptHashData(hash, buf, got, 0) != 0) { ok = false; break; }
                }
                if (ok && BCryptFinishHash(hash, out, 32, 0) != 0) ok = false;
                BCryptDestroyHash(hash);
            }
            BCryptCloseAlgorithmProvider(alg, 0);
        }
        if (ok) *size = (unsigned long long)fileSize.QuadPart;
    }
    CloseHandle(file);
    return ok;
}

bool ImageFileDigest(unsigned long long* size, unsigned char hash[32]) {
    static int checked = 0;
    static bool result = false;
    static unsigned long long cachedSize = 0;
    static unsigned char cachedHash[32] = {};
    if (!checked) {
        checked = 1;
        result = HashHostFile(&cachedSize, cachedHash);
    }
    if (!result) return false;
    *size = cachedSize;
    memcpy(hash, cachedHash, 32);
    return true;
}

}
