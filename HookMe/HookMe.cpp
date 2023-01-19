#include "Objects.h"
#include "../Entry Spoof/tools/Windows_NoBs.h"

void JustReturn() { // filler funcs
    return;
}

void MathReturn() {
    int a, b, c, d, e, f, g = 0;

    a = 30;
    b = 51235;
    c = 1231 - 3;
    d = 534;

    e = c;
    f = a * b;
    g += a * 2;

    69 + 69;

    JustReturn();
    return;
}

void general_out(InheritingObject& io) {
    std::cout << "Inheriting Object Address: " << &io << "\n";

    std::cout << "IO Object Hello: ";
    InheritingObject{}.printHello();

    std::cout << "IO Object Goodbye: ";
    InheritingObject{}.printGoodbye();
    std::cout << "=======================\n\n";
}

int main() {
    std::cout << "[Started]\n\n";
    static InheritingObject io; // static object to grab from dll
    bool hello_spam = 0;
    bool loaded = 0;

    std::cout << "+-----------------------------------------------------+\n";
    std::cout << "|                         Control                     |\n";
    std::cout << "|-----------------------------------------------------|\n";
    std::cout << "|[NUMPAD 1]: to load the dll and start the hook.      |\n";
    std::cout << "|[NUMPAD 2]: to unload the dll and restore the hook.  |\n";
    std::cout << "|[NUMPAD 3]: to call all the current v funcs.         |\n";
    std::cout << "|[NUMPAD 4]: to turn the exe spam on and off.         |\n";
    std::cout << "+-----------------------------------------------------+\n\n";


    while (!GetAsyncKeyState(VK_END)) {
        if (hello_spam) {
            // Calling only the virtual funcs to demonstrate
            general_out(io);
        }

        if (GetAsyncKeyState(VK_NUMPAD3)) {
            general_out(io);
            Sleep(200);
        }

        if (GetAsyncKeyState(VK_NUMPAD4)) {
            
            std::cout << "[Spam]: ";
            if (hello_spam)  // ternary operator was not working 
                std::cout << "off\n\n";
            else
                std::cout << "on\n\n";

            hello_spam = !hello_spam;
            Sleep(200); // helps avoid press and hold change spam;
        }

        if(GetAsyncKeyState(VK_NUMPAD1) && !loaded) {
            std::cout << "\nLoading:\n";
            LoadLibrary(L"./EAS.dll");
            loaded = 1;
        }

        MathReturn(); 
        Sleep(1000);
    }

    std::cout << "Cool.\n";
}
