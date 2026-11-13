#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

bool IsMemoryReadable(const void* addr, size_t size) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    const DWORD protect = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    const bool readable =
        protect == PAGE_READONLY ||
        protect == PAGE_READWRITE ||
        protect == PAGE_EXECUTE_READ ||
        protect == PAGE_EXECUTE_READWRITE ||
        protect == PAGE_EXECUTE_WRITECOPY ||
        protect == PAGE_WRITECOPY;
    if (!readable) {
        return false;
    }
    const auto start = reinterpret_cast<uintptr_t>(addr);
    const auto regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return start + size <= regionEnd;
}

bool WriteProcessBytes(uintptr_t rva, const void* bytes, size_t size) {
    auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (base == 0) {
        return false;
    }
    void* patchAddr = reinterpret_cast<void*>(base + rva);
    DWORD oldProtect = 0;
    if (!VirtualProtect(patchAddr, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    std::memcpy(patchAddr, bytes, size);
    FlushInstructionCache(GetCurrentProcess(), patchAddr, size);
    VirtualProtect(patchAddr, size, oldProtect, &oldProtect);
    return true;
}

float ReadIniFloat(const std::string& iniPath, const char* section, const char* key, float fallback) {
    char buffer[64]{};
    char defStr[64]{};
    _snprintf_s(defStr, sizeof(defStr), _TRUNCATE, "%.6g", fallback);
    GetPrivateProfileStringA(section, key, defStr, buffer, sizeof(buffer), iniPath.c_str());
    char* endPtr = nullptr;
    float val = std::strtof(buffer, &endPtr);
    if (endPtr == buffer) {
        return fallback;
    }
    return val;
}

std::string GetSiblingIniPath(HMODULE hModule) {
    char path[MAX_PATH]{};
    GetModuleFileNameA(hModule, path, MAX_PATH);
    std::string iniPath(path);
    size_t dotPos = iniPath.find_last_of('.');
    size_t slashPos = iniPath.find_last_of("\\/");
    if (dotPos != std::string::npos && (slashPos == std::string::npos || dotPos > slashPos)) {
        return iniPath.substr(0, dotPos) + ".ini";
    }
    return iniPath + ".ini";
}

void ApplyPatch(HMODULE hModule) {
    const std::string iniPath = GetSiblingIniPath(hModule);

    float fadeStart = ReadIniFloat(iniPath, "Terrain", "ForegroundFadeStart", 112.0f);
    float fadeEnd = ReadIniFloat(iniPath, "Terrain", "ForegroundFadeEnd", 128.0f);

    fadeStart = std::max(0.0f, fadeStart);
    if (fadeEnd <= fadeStart + 1.0f) {
        fadeEnd = fadeStart + 1.0f;
    }

    const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (base == 0) {
        return;
    }

    // Retail Fable.exe: CEngineLandscapeRenderer::CEngineLandscapeRenderer
    //   00B6927E: mov dword ptr [esi+614h], 48.0f (0x42400000)
    //   00B69288: mov dword ptr [esi+618h], 64.0f (0x42800000)
    static constexpr BYTE kRetailSig[20] = {
        0xC7, 0x86, 0x14, 0x06, 0x00, 0x00, 0x00, 0x00, 0x40, 0x42,
        0xC7, 0x86, 0x18, 0x06, 0x00, 0x00, 0x00, 0x00, 0x80, 0x42
    };
    const auto* retailPtr = reinterpret_cast<const BYTE*>(base + 0x76927E);
    if (IsMemoryReadable(retailPtr, sizeof(kRetailSig)) &&
        std::memcmp(retailPtr, kRetailSig, sizeof(kRetailSig)) == 0) {
        WriteProcessBytes(0x769284, &fadeStart, sizeof(float));
        WriteProcessBytes(0x76928E, &fadeEnd, sizeof(float));
        return;
    }

    // Debug ego_r.exe fallback:
    //   009AA7CC: fld ds:[...] ; fstp dword ptr [esi+0EA0h]
    //   009AA7D8: fld ds:[...] ; fstp dword ptr [esi+0EA4h]
    const auto* egoPtr = reinterpret_cast<const BYTE*>(base + 0x5AA7CC);
    if (IsMemoryReadable(egoPtr, 24) &&
        egoPtr[0] == 0xD9 && egoPtr[1] == 0x05 &&
        egoPtr[6] == 0xD9 && egoPtr[7] == 0x9E &&
        egoPtr[8] == 0xA0 && egoPtr[9] == 0x0E && egoPtr[10] == 0x00 && egoPtr[11] == 0x00 &&
        egoPtr[12] == 0xD9 && egoPtr[13] == 0x05 &&
        egoPtr[18] == 0xD9 && egoPtr[19] == 0x9E &&
        egoPtr[20] == 0xA4 && egoPtr[21] == 0x0E && egoPtr[22] == 0x00 && egoPtr[23] == 0x00) {
        BYTE replacement[24] = {
            0xC7, 0x86, 0xA0, 0x0E, 0x00, 0x00, 0, 0, 0, 0,
            0xC7, 0x86, 0xA4, 0x0E, 0x00, 0x00, 0, 0, 0, 0,
            0x90, 0x90, 0x90, 0x90
        };
        std::memcpy(replacement + 6, &fadeStart, sizeof(float));
        std::memcpy(replacement + 16, &fadeEnd, sizeof(float));
        WriteProcessBytes(0x5AA7CC, replacement, sizeof(replacement));
    }
}

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        ApplyPatch(hModule);
    }
    return TRUE;
}
