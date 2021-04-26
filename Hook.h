/* This file is part of NoCRC by ByteCode777, licensed under the MIT license:
*
* MIT License
*
* Copyright (c) ByteCode777 2021
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#pragma once
#include <Windows.h>

namespace NoCRC
{
    enum HookStatus
    {
        FAILED_VIRTUALPROTECT_FUNCTION = 1,
        FAILED_ALLOCATE = 2,
        INVALID_PARAMS = 3,
        SUCCESS = 4
    };

    HookStatus HookFunction(uint64_t FunctionToHook, void* FunctionToDetour, void** Original, int BytesToOverwrite)
    {
        if (!FunctionToHook || !FunctionToDetour || !Original || (BytesToOverwrite < 14))
            return HookStatus::INVALID_PARAMS;

        // Was testing out lambdas.
        auto NopIncompleteInstructions = [&](uint64_t FunctionAddress, ULONG Length)
        {
            for (int i = 0; i < Length; i++)
                *(unsigned char*)(FunctionToHook + i) = 0x90;
        };

        auto AddJump = [&](uint64_t FunctionAddress, void* DetourAddress)
        {
            unsigned char Jump[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            *(uint64_t*)(Jump + 6) = uint64_t(DetourAddress);
            memcpy((void*)FunctionAddress, &Jump, 14);
        };


        DWORD old;

        void* Original_ = VirtualAlloc(0, BytesToOverwrite + 14, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!Original_) return HookStatus::FAILED_ALLOCATE;

        //Make our return to original function jump
        memcpy(Original_, (void*)FunctionToHook, BytesToOverwrite);
        AddJump(uint64_t(Original_) + BytesToOverwrite, (void*)(FunctionToHook + 14));
        memcpy(Original, &Original_, sizeof(Original_));

        //Make a jump to our detour
        if (!VirtualProtect((void*)FunctionToHook, BytesToOverwrite, PAGE_EXECUTE_READWRITE, &old)) return HookStatus::FAILED_VIRTUALPROTECT_FUNCTION;
        NopIncompleteInstructions(FunctionToHook, BytesToOverwrite);
        AddJump(FunctionToHook, FunctionToDetour);
        if (!VirtualProtect((void*)FunctionToHook, BytesToOverwrite, old, &old)) return HookStatus::FAILED_VIRTUALPROTECT_FUNCTION;

        return HookStatus::SUCCESS;
    }
}