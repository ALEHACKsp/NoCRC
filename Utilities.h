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
#include <cstdint>

uint64_t FindPattern(const char* Module, const char* Pattern, DWORD Length, unsigned char Mask)
{
	uint64_t BaseAddress = uint64_t(GetModuleHandleA(Module));
	Length--;

	PIMAGE_DOS_HEADER DosHeader = PIMAGE_DOS_HEADER(BaseAddress);
	PIMAGE_NT_HEADERS64 NtHeader = PIMAGE_NT_HEADERS64(DosHeader->e_lfanew + BaseAddress);
	DWORD ImageLength = NtHeader->OptionalHeader.SizeOfImage;

	bool Found = false;

	for (uint64_t CurrentByte = 0; CurrentByte <= (ImageLength - Length); CurrentByte++)
	{
		uint64_t CurrentAddress = BaseAddress + CurrentByte;
		for (int i = 0; i < Length; i++)
		{
			if (*(unsigned char*)(&Pattern[0] + i) == Mask)
				continue;

			if (*(unsigned char*)(CurrentAddress + i) != *(unsigned char*)(&Pattern[0] + i))
			{
				Found = false;
				break;
			}
			else
				Found = true;
		}

		if (Found)
			return CurrentAddress;
	}
}