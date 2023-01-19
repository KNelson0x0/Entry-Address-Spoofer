#pragma once
void debug_msg(const char* msg, ...) {
#ifdef _DEBUG
	static const auto MAX_BUFFER_SIZE = 1024;
	static char buffer[MAX_BUFFER_SIZE] = "";
	va_list va;
	va_start(va, msg);
	vsnprintf_s(buffer, MAX_BUFFER_SIZE, msg, va);
	va_end(va);
	printf("%s \n", buffer);
#endif
}

namespace tools { 
	template <typename Func>
	bool place_vmt_hook(unsigned int table_address, Func func, int index) { // for init only.
		DWORD old_protect;
		unsigned int* vtable_func = (unsigned int*)(table_address + ((index) * 4));
		VirtualProtect(vtable_func, 4, PAGE_READWRITE, &old_protect);
		*vtable_func = (unsigned int)func;
		VirtualProtect(vtable_func, 4, old_protect, &old_protect);
		return 1;
	}
	void copy_memory(void* address, char* out_buffer, int length) {
		DWORD oldProtect;

		VirtualProtect((LPVOID)address, length, PAGE_READONLY, &oldProtect);
		for (int i = 0; i < length; i++) {
			out_buffer[i] = *(char*)((unsigned int)address + i);
		}
		VirtualProtect(address, length, oldProtect, &oldProtect);
	}
	void write_memory(void* address, char* in_buffer, int length) {
		DWORD oldProtect;

		VirtualProtect((LPVOID)address, length, PAGE_READWRITE, &oldProtect);
		for (int i = 0; i < length; i++) {
			*(char*)((unsigned int)address + i) = in_buffer[i];
		}
		VirtualProtect(address, length, oldProtect, &oldProtect);
	}
	void write_memory(void* address, const char* in_buffer, int length) {
		DWORD oldProtect;

		VirtualProtect((LPVOID)address, length, PAGE_READWRITE, &oldProtect);
		for (int i = 0; i < length; i++) {
			*(char*)((unsigned int)address + i) = in_buffer[i];
		}
		VirtualProtect(address, length, oldProtect, &oldProtect);
	}
	unsigned int get_base_of_code(const char* szModName) {
		HMODULE mod_base = (HMODULE)GetModuleHandleA(szModName);
		PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)mod_base;

		if (!pDOSHeader) return 0; // code? - technically extra
		PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(((DWORD)mod_base) + pDOSHeader->e_lfanew); // extra
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeaders);

		for (WORD i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) { // loop through sections until .text is found.
			if (!std::strcmp(".text", (const char*)section->Name)) i = pNTHeaders->FileHeader.NumberOfSections;
			else section++;
		}

		DWORD mod_code_base = (DWORD)mod_base + section->VirtualAddress; // still being fancy

		return mod_code_base;
	}
	unsigned int get_modbase(const char* szModName) {
		return (unsigned int)GetModuleHandleA(szModName);
	}

	// compile time vers
	template<size_t N>
	unsigned int find_sig_mask(const char* szModName, unsigned int start_address, const char(&pattern)[N], const char(&mask)[N], bool use_mask) {
		int hits = 0;
		int size = 0;
		HMODULE mod_base = (HMODULE)GetModuleHandleA(szModName);
		PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)mod_base;
		PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(((DWORD)mod_base) + pDOSHeader->e_lfanew); // extra

		if (!pDOSHeader) return 0; // code? - technically extra
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeaders);

		for (WORD i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) { // loop through sections until .text is found.
			if (!std::strcmp(".text", (const char*)section->Name)) i = pNTHeaders->FileHeader.NumberOfSections;
			else section++;
		}

		DWORD mod_code_base = (DWORD)mod_base + section->VirtualAddress;

		size = pNTHeaders->OptionalHeader.SizeOfCode;
		if (start_address) size = pNTHeaders->OptionalHeader.SizeOfCode - start_address;
		if (!start_address) start_address = mod_code_base;
		
		for (DWORD i = 0; i < size; i++) {
			char c = *(char*)(start_address + i);

			if (use_mask) {
				if (hits >= N - 1) return (UINT)(start_address + i - (N - 1)); // updated 
				else if (mask[hits] == 'x' && c == pattern[hits]) hits++;
				else if (mask[hits] == '?' || mask[hits] == '*' && c == pattern[hits]) hits++;
				else {
					i -= (hits);
					hits = 0;
				}
			} else { // really did the extra
				if (hits >= N - 1) return (UINT)(start_address + i - (N - 1));
				else if (pattern[hits] == '\?') hits++;
				else if (c == pattern[hits]) hits++;
				else {
					i -= (hits);
					hits = 0;
				}
			}
		}

		return 0;
	}
	template<size_t N>
	unsigned int find_sig(const char* szModName, unsigned int start_address, const char(&pattern)[N]) {
		char a[N];
		return find_sig_mask(szModName, start_address, pattern, a, false); // could also just pass pattern twice
	}
	template<size_t N>
	unsigned int find_sig(const char* szModName, unsigned int start_address, const char(&pattern)[N], const char(&mask)[N]) {
		return find_sig_mask(szModName, start_address, pattern, mask, true);
	}

	// str vers
	unsigned int find_sig_mask(const char* szModName, unsigned int start_address, std::string pattern, std::string mask, bool use_mask) {
		size_t N = pattern.size();
		int hits = 0;
		int size = 0;
		unsigned int protect_start;
		unsigned int protect_size = 4056;
		DWORD old_protect = PAGE_EXECUTE_READ;
		HMODULE mod_base = (HMODULE)GetModuleHandleA(szModName);
		PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)mod_base;
		PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(((DWORD)mod_base) + pDOSHeader->e_lfanew); // extra

		if ((pattern.size() != mask.size()) && mask.size() != 0) {
			debug_msg("[find_sig_mask]> Mask and Pattern not the same size.");
			return 0;
		}
		if (!pDOSHeader) return 0; // code? - technically extra
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeaders);

		for (WORD i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) { // loop through sections until .text is found.
			if (!std::strcmp(".text", (const char*)section->Name)) i = pNTHeaders->FileHeader.NumberOfSections;
			else section++;
		}

		DWORD mod_code_base = (DWORD)mod_base + section->VirtualAddress;

		size = pNTHeaders->OptionalHeader.SizeOfCode;
		if (start_address) size = pNTHeaders->OptionalHeader.SizeOfCode - start_address;
		if (!start_address) start_address = mod_code_base;


		protect_start = start_address;

		for (DWORD i = 0; i < size; i++) {

			if (i % protect_size == 0) {
				if ((size - i) < protect_size) protect_size = (size - i);
				if (i != 0) VirtualProtect(LPVOID(protect_start + i - protect_size), protect_size, old_protect, &old_protect);

				VirtualProtect(LPVOID(protect_start + i), protect_size, old_protect, &old_protect);
			}

			char c = *(char*)(start_address + i);

			if (use_mask) {
				if (hits >= N - 1) return (UINT)(start_address + i - (N - 1)); // updated 
				else if (mask[hits] == 'x' && c == pattern[hits]) hits++;
				else if (mask[hits] == '?' || mask[hits] == '*' && c == pattern[hits]) hits++;
				else {
					i -= (hits);
					hits = 0;
				}
			} else { // really did the extra
				if (hits >= N - 1) return (UINT)(start_address + i - (N - 1));
				else if (pattern[hits] == '\?') hits++;
				else if (c == pattern[hits]) hits++;
				else {
					i -= (hits);
					hits = 0;
				}
			}
		}

		return 0;
	}
	unsigned int find_sig(const char* szModName, unsigned int start_address, std::string pattern) {
		std::string a;
		return find_sig_mask(szModName, start_address, pattern, a, false); // could also just pass pattern twice
	}
	unsigned int find_sig(const char* szModName, unsigned int start_address, std::string pattern, std::string mask) {
		return find_sig_mask(szModName, start_address, pattern, mask, true);
	}
};

