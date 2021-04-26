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

#include <windows.h>
#include <iostream>
#include "SampleCRC.h"
#include "NoCRC.h"

float ExampleFloats[5];

void SampleAntiCheatHashCheckRoutine()
{
    DWORD OldHash = RtlComputeCrc32(0, (PBYTE)&ExampleFloats, sizeof(ExampleFloats));

    while (true)
    {
        DWORD NewHash = RtlComputeCrc32(0, (PBYTE)&ExampleFloats, sizeof(ExampleFloats));

        if (NewHash != OldHash)
            printf("Failed Integrity Checks! Hash: 0x%lx\n", NewHash);
        else
            printf("Succeeded Integrity Checks! Hash: 0x%lx\n", NewHash);

        Sleep(100);
    }
}

int main()
{
    CreateThread(0, 0, LPTHREAD_START_ROUTINE(SampleAntiCheatHashCheckRoutine), 0, 0, 0); // Create a new thread for sample ac crc check.


    NoCRC::SetupCRCTableTrap(); // Attempt to find crc table then walk address to get compute function and hook.

    Sleep(1000); // Allow success for 1 second.

    ExampleFloats[2] = 1.f; // Make check fail.

    Sleep(1000); // Wait for 1 second.

    NoCRC::CanEnableCRCSpoof = true; // Enable spoof.

    Sleep(-1); // Stall main thread indefinitely 
}