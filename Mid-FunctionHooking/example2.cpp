#include <windows.h>
#include <iostream>

BYTE originalBytes[5]; // Store the original bytes at the hook point
void* targetFunctionAddr = reinterpret_cast<void*>(0x12345678); // Replace with the specific address
void* hookFunctionAddr = reinterpret_cast<void*>(&HookedFunction); // Address of the hook function

// Hook function that will be called
void HookedFunction() {
    std::cout << "Hooked at specific address!" << std::endl;

    // Optional: Restore original bytes if you want to run the original code
    WriteProcessMemory(GetCurrentProcess(), targetFunctionAddr, originalBytes, sizeof(originalBytes), nullptr);

    // Jump back to the original function after your code, if necessary
    // You would need to calculate the address after the hook point
    // Example: Go back to targetFunctionAddr + <offset after hook>
}

// Set the hook by writing a JMP instruction to the hook function
void SetMidFunctionHook() {
    DWORD oldProtect;
    VirtualProtect(targetFunctionAddr, sizeof(originalBytes), PAGE_EXECUTE_READWRITE, &oldProtect);

    // Save original bytes to restore later
    memcpy(originalBytes, targetFunctionAddr, sizeof(originalBytes));

    // Calculate the relative offset for the JMP instruction
    int32_t offset = (int32_t)((uintptr_t)hookFunctionAddr - (uintptr_t)targetFunctionAddr - 5);

    // Write the JMP opcode and offset to target function address
    BYTE jumpInstruction[5] = { 0xE9 }; // JMP opcode
    memcpy(jumpInstruction + 1, &offset, sizeof(offset)); // Write offset after the JMP opcode
    WriteProcessMemory(GetCurrentProcess(), targetFunctionAddr, jumpInstruction, sizeof(jumpInstruction), nullptr);

    VirtualProtect(targetFunctionAddr, sizeof(originalBytes), oldProtect, &oldProtect);
}

// Restore original bytes to remove the hook
void RemoveMidFunctionHook() {
    DWORD oldProtect;
    VirtualProtect(targetFunctionAddr, sizeof(originalBytes), PAGE_EXECUTE_READWRITE, &oldProtect);

    // Restore original bytes
    WriteProcessMemory(GetCurrentProcess(), targetFunctionAddr, originalBytes, sizeof(originalBytes), nullptr);

    VirtualProtect(targetFunctionAddr, sizeof(originalBytes), oldProtect, &oldProtect);
}

int main() {
    SetMidFunctionHook();
    // Call or trigger the target function here
    RemoveMidFunctionHook();

    return 0;
}
