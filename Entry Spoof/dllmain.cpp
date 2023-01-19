#include "includes.h"
#include "tools/tools_include.h"
#include "EAS.h"
#include "hooks.h"

// EAS Poc
// - v1 moved from priv to public github


#define main APIENTRY DllMain

hooks::printHello::Fn* hooks::printHello::original;

void __fastcall hooks::printHello::hooked(void* ecx) {
    std::cout << "I'm a different function from the injected dll\n";
}

DWORD __stdcall Init(HMODULE hModule) {
    std::cout << "injected\n";
    std::cout << "Base of code: " << std::hex << tools::get_base_of_code("HookMe.exe") << "\n";
    
    // find object
    void* object_class = *(void**)(tools::find_sig("HookMe.exe", 0, "\xB9\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xC7\x45\xFC", "x????x????xxx") + 1);

    // start hook 
    auto hello_hook = EAS<DEF_T(hooks::printHello::hooked)>("HookMe.exe", object_class);
    hooks::printHello::original = hello_hook.place_vmt_hook<HOOK(printHello)>(&hooks::printHello::hooked, 1, 0);

    // Wait until end
    while (!GetAsyncKeyState(VK_NUMPAD2) & 1) Sleep(50);
    
    // cleanup and free the dll
    hello_hook.~EAS();
    std::cout << "leaving\n"; 
    FreeLibraryAndExitThread(hModule, 0);
    return 1;
}

int main( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CloseHandle(CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(Init), hModule, NULL, NULL));
    default: // fall-through
        break;
    }
    return TRUE;
}

