#pragma once
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>

extern HMODULE dbghelp_dll;
DWORD WINAPI Load(LPVOID lpParam);