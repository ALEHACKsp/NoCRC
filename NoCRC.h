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
#include <stdio.h>
#include "Utilities.h"
#include "Hook.h"

namespace NoCRC
{
	uint64_t CRCTable = 0;
	uint64_t CRCFunction = 0;
	bool CanEnableCRCSpoof = false;
	PVOID ExceptionHandler = 0;
	void* Dictionary = 0;
	DWORD OldProtect = 0;

	typedef struct DictionaryStructure_t
	{
		uint64_t Location;
		DWORD Hash;
	} DictionaryStructure, * PDictionaryStructure;

#define GetStructureSizeFromNum(num) sizeof(DictionaryStructure) * num

	PDictionaryStructure GetFunctionInfo(uint64_t Address, void* Dictionary)
	{
		for (int i = 0; PDictionaryStructure(uint64_t(Dictionary) + i)->Hash != 0; i++)
		{
			PDictionaryStructure CurrentEntry = PDictionaryStructure(uint64_t(Dictionary) + i);
			if (CurrentEntry->Location == Address)
				return CurrentEntry;
		}

		return 0;
	}

	void AddEntry(uint64_t Address, DWORD Hash, void* Dictionary)
	{
		for (int i = 0;; i++)
		{
			PDictionaryStructure CurrentEntry = PDictionaryStructure(uint64_t(Dictionary) + (i * sizeof(DictionaryStructure)));
			if (Address == CurrentEntry->Location)
				break;

			if (!CurrentEntry->Location)
			{
				CurrentEntry->Location = Address;
				CurrentEntry->Hash = Hash;

				printf("[+] Added Hash Entry: Index(%d) Location(0x%llx) Hash(0x%lx)\n", i, CurrentEntry->Location, CurrentEntry->Hash);

				break;
			}
		}
	}

	DWORD(__fastcall* OriginalCRC)(DWORD Initial, uint64_t Data, INT Length);
	DWORD __fastcall HookedCRC(DWORD Initial, uint64_t Data, INT Length)
	{
		DWORD Hash = OriginalCRC(Initial, Data, Length);

		AddEntry(Data, Hash, Dictionary);

		if (CanEnableCRCSpoof == true)
			for (int i = 0; i < Length; i++)
			{
				PDictionaryStructure Structure = GetFunctionInfo(Data + i, Dictionary);
				if (Structure)
				{
					printf("[+] Spoofed Hash: Location(0x%llx)  Spoofed Hash(0x%lx)  Hash(0x%lx)\n", Structure->Location, Structure->Hash, Hash);
					return Structure->Hash;
				}
			}

		return Hash;
	}

	long VEH(PEXCEPTION_POINTERS Ex)
	{
		//For some reason my exception handler was misaligning the address and it was 80ish bytes behind.
		//If invalid results then debug and fix this.
		uint64_t ExceptionAddress = uint64_t(Ex->ExceptionRecord->ExceptionAddress) + 80;

		if (Ex->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		{
			for (int i = 0; i < 0xFF; i++)
			{
				if (*(unsigned char*)(ExceptionAddress - i) == 0xCC) // Loop till int 3 padding is found
				{
					CRCFunction = ExceptionAddress - (i - 1);
					VirtualProtect((void*)CRCTable, 256 * 4, OldProtect, &OldProtect);
					printf("[+] Found Possible CRC Function: Location(0x%llx)  LocationSubBase(0x%llx)\n", CRCFunction, CRCFunction - uint64_t(GetModuleHandleA(0)));

					// Some CRC functions are modified slightly, so I'll recommend you to dump the executable and then rebase the LocationSubBase with the executable base and fix instruction overwrite length.
					HookStatus Err = HookFunction(CRCFunction, HookedCRC, (void**)&OriginalCRC, 18);
					if (Err != HookStatus::SUCCESS)
						printf("[-] Failed To Hook CRC Function: Error(%d)\n", Err);

					RemoveVectoredExceptionHandler(ExceptionHandler);

					return EXCEPTION_CONTINUE_EXECUTION;
				}
			}

			Ex->ContextRecord->EFlags |= 0x100; // Single step.
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (Ex->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
		{
			VirtualProtect((void*)CRCTable, 256 * 4, PAGE_READWRITE | PAGE_GUARD, &OldProtect);
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		return EXCEPTION_CONTINUE_SEARCH;
	}

	bool SetupCRCTableTrap()
	{
		if (!Dictionary)
		{					//	Change number higher like 10k if using in a game or something.
			Dictionary = VirtualAlloc(0, GetStructureSizeFromNum(5), MEM_COMMIT, PAGE_READWRITE);
			printf("[+] Dictionary Allocated: Location(0x%llx)\n", Dictionary);
		}

		if (!CRCTable)
		{
			CRCTable = FindPattern(0, "\x00\x00\x00\x00\x96\x30\x07\x77\x2C\x61\x0E\xEE\xBA\x51\x09", 16, 0xCC);
			if (!CRCTable)
				return false;
			printf("[+] CRC Table: Location(0x%llx)\n", CRCTable);
		}


		ExceptionHandler = AddVectoredExceptionHandler(1, VEH);
		VirtualProtect((void*)CRCTable, 256 * 4, PAGE_READWRITE | PAGE_GUARD, &OldProtect);

		printf("[+] Done setting up trap!\n");
	}
}