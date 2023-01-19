#pragma once

#include <time.h>
#include <vector>

#define DEF_T(x)       decltype(x)              // shorten decltype
#define DEF_T_A(x)     decltype(&x)             // define address type, use for Functions
#define VMT_TYPES(x,y) decltype(x), decltype(y) // pass value, return value
#define VMT_TYPE(x)    VMT_TYPES(&x, x)         // pass value, get type for address of value and the value
#define HOOK(x) decltype(hooks::x::hooked), decltype(hooks::x::original)

template<typename func>
class EAS { // x86 only rn.
public: // p-types
	struct GadgetInfo {
		GadgetInfo() : address(0), size(0) {};
		GadgetInfo(unsigned int address, unsigned int size) : address(address), size(size) {};
		unsigned int address;
		unsigned int size;

		bool created() { return (address && size); }
	};
	struct HookInfo {
		HookInfo(int index) : index(index) {};
		std::vector<GadgetInfo> gadget_chain;
		unsigned int* stolen_vmt_addy;
		unsigned int stolen_vmt_value = -1;
		int index;
	};
	class GadgetFactory { // yes ik ik, not a 'real' gadget, more like weird thunks or shellcode. I like the name. Im keeping the name.
	private: // p-Types
		struct Gadget {
			Gadget(const char* bytes, int max_size) : bytes(bytes), max_size(max_size) {};
			const char* bytes;
			unsigned int max_size;
		};
	private: // p-vars
		std::vector<Gadget> small_gadgets = {
			Gadget("\x55\x57\x5F\x5D\xE9", 9),
			Gadget("\x55\x83\xC4\x04\xE9", 9),
			Gadget("\x40\x48\xE9", 7)
		};
	private: // p-Funcs
		unsigned int find_space(const char* sz_mod_name, int preferred_size) {
			std::string space;
			for (int i = 0; i < preferred_size; i++)
				space += "\xCC";

			return tools::find_sig(sz_mod_name, 0, space.c_str());
		}
		void build(unsigned int gadget_addy, Gadget gadget, unsigned int jump_to) {
			DWORD old_protect;

			jump_to = (jump_to - (gadget_addy + gadget.max_size)) - 0; // of by 2
			VirtualProtect((LPVOID)gadget_addy, 2, PAGE_READWRITE, &old_protect);
			tools::write_memory((void*)gadget_addy, gadget.bytes, gadget.max_size - 4);
			*(UINT*)(gadget_addy + gadget.max_size - 4) = jump_to;
			VirtualProtect((LPVOID)gadget_addy, 2, old_protect, &old_protect);
		}
	public:
		GadgetInfo make_gadget(const char* sz_mod_name, unsigned int jump_to) {
			unsigned int gadget = 0;
			int size = 0;
			srand(time(NULL) + (time(NULL) % 156));

			if (gadget = find_space(sz_mod_name, 9)) {
				size = 9;
				build(gadget, small_gadgets[(rand() % 2)], jump_to);
			} else if (gadget = find_space(sz_mod_name, 7)) {
				build(gadget, small_gadgets[2], jump_to);
				size = 7;
			} else {
				debug_msg("[GadgetFactory]> Could not find space in module: ");
				debug_msg(sz_mod_name);
				debug_msg("!\n");
				return GadgetInfo(0, 0);
			}

			return GadgetInfo(gadget, size);
		}
	};
	public: // p-functions
		EAS(const char* szModName, void* to_class) : szModName(szModName), vmt_base_addy((*(unsigned int*)to_class)) {}; // regular initializer object
		EAS(const char* szModName, unsigned int vtable) : szModName(szModName), vmt_base_addy(vtable) {};
		EAS(const char* szModName, func Func, unsigned int gadgets, void* to_class, int index) : our_func((unsigned int)Func), vmt_base_addy((*(unsigned int*)to_class)), curr_index(0) { // will initialize and hook, object
			if (Init(szModName, gadgets, index))
				place_vmt_hook(vmt_base_addy, index);
		};
		EAS(const char* szModName, func Func, unsigned int gadgets, unsigned int vtable, int index) : our_func((unsigned int)Func), vmt_base_addy(vtable), curr_index(0) { // will initialize and hook, vtable
			if (Init(szModName, gadgets, index))
				place_vmt_hook(vmt_base_addy, index);
		};
		~EAS() {
			for (int i = 0; i < hooks.size(); i++) {
				if (hooks[i].stolen_vmt_value != -1) { // if anything was done, restore original index
					DWORD old_protect;
					VirtualProtect(hooks[i].stolen_vmt_addy, 1, PAGE_READWRITE, &old_protect);
					*hooks[i].stolen_vmt_addy = hooks[i].stolen_vmt_value;
					VirtualProtect(hooks[i].stolen_vmt_addy, 1, old_protect, &old_protect);
				}

				for (int ii = 0; ii < hooks[i].gadget_chain.size(); ii++)
					tools::write_memory((void*)hooks[i].gadget_chain[ii].address, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC", hooks[i].gadget_chain[ii].size);
			}
		}
		HookInfo get_hook(int index) { // Finds hook by index
			for (HookInfo i : hooks)
				if (i.index == index) return i;

			debug_msg("[EAS]> Could not find desired hook.\n");
			return HookInfo(-1);
		}
		void Unhook() {
			~EAS();
			debug_msg("[EAS]> Restored vtables and destroyed gadgets.\n");
		}
		template <class T, typename TT>
		TT place_vmt_hook(T func, int gadgets, int index) { // for other indices on the same v-table
			unsigned int our_func = (unsigned int)func;

			if (hooks.empty())
				curr_index = 0;
			else
				curr_index++;
			// -- Gadgets can fit check -- \\ 
			if (!gadgets_can_be_generated(gadgets)) {
				debug_msg("[EAS]> Gadgets cannot be generated in ");
				debug_msg(szModName);
				debug_msg(" Stopping!");
				return (TT)0x0;
			}
			// -- Start -- \\ 
			hooks.push_back(HookInfo(index));
			make_gadget(szModName, our_func);
			for (int i = 1; i < gadgets; i++)
				make_gadget(szModName, hooks[curr_index].gadget_chain[i - 1].address);

			place_vmt_hook(vmt_base_addy, index);

			// -- Store the original func in the original func ptr -- \\ 
			unsigned int original = get_hook(index).stolen_vmt_value;
			return (TT)original; 		 // return the original function
		}
		void rehook(int index) {
			if (hooks.empty()) {
				debug_msg("[EAS]> Nothing to Rehook!\n");
				return;
			}
			place_vmt_hook(vmt_base_addy, index);
		}
		template<typename T>
		T get_func(int index) {
			return (T)get_hook(index).stolen_vmt_value;;
		}
	private: // pv-functions
		bool Init(const char* szModName, int gadgets, int index) {
			// -- Stupid User Check -- \\ 
			if (!hooks.empty()) { // don't call it twice. 
				debug_msg("[EAS]> This instance has already been initialized!\n");
				return 0;
			}
			// -- Gadgets can fit check -- \\ 
			if (!gadgets_can_be_generated(gadgets)) {
				debug_msg("[EAS]> Gadgets cannot be generated! Stopping!\n");
				return 0;
			}
			// -- Start -- \\ 
			hooks.push_back(HookInfo(index));
			make_gadget(szModName, our_func); // gadget time
			for (int i = 1; i < gadgets; i++)
				make_gadget(szModName, hooks[curr_index].gadget_chain[i - 1].address);

			return 1;
		}
		bool gadgets_can_be_generated(int gadgets) {
			unsigned int f_gadget_space = tools::find_sig(szModName, 0, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC");

			populate_acceptable_address_range();
			for (int i = 1; i < gadgets; i++) {
				f_gadget_space = tools::find_sig(szModName, f_gadget_space + 27, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC");
				if (!f_gadget_space) return 0;
				if (f_gadget_space < min_safe_address || f_gadget_space > max_safe_address) return 0; // if gadget space is not in the module bother don't bother generating them. Use a different hook type.
			}
			return 1;
		}
		bool place_vmt_hook(unsigned int table_address, int index) { // for init only.
			DWORD old_protect;
			unsigned int* vtable_func = (unsigned int*)(table_address + ((index) * 4));
			hooks[curr_index].stolen_vmt_addy = vtable_func;
			hooks[curr_index].stolen_vmt_value = *vtable_func;
			VirtualProtect(vtable_func, 4, PAGE_READWRITE, &old_protect);
			*vtable_func = get_hook(index).gadget_chain.back().address;
			VirtualProtect(vtable_func, 4, old_protect, &old_protect);
			return 1;
		}
		void make_gadget(const char* sz_mod_name, unsigned int jump_to) { // default single gadget
			DWORD old_protect;
			srand(time(NULL) + hooks.size());
			int esp_sub = rand() % 150;
			int nop_amt = rand() % 4; // no need to get crazy now.
			unsigned int gadget = tools::find_sig(sz_mod_name, 0, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC");
			GadgetInfo gi;

			if (!gadget) { // make a smaller simpler gadget if cant find align section to place in
				gi = GadgetFactory{}.make_gadget(sz_mod_name, jump_to);
			} else { // default 
				jump_to = (jump_to - (gadget + 18 + nop_amt)) - 5;

				VirtualProtect((LPVOID)gadget, 2, PAGE_READWRITE, &old_protect);

				char mislead[25] = { 0x55, 0x8B, 0xEC, 0x81, 0xEC };
				mislead[5] = esp_sub;

				for (int i = 0; i < nop_amt; i++) // i really hate using known functions
					mislead[9 + i] = 0x90;

				tools::write_memory((void*)(mislead + 9 + nop_amt), "\x81\xC4", 2);
				mislead[11 + nop_amt] = esp_sub;
				tools::write_memory((void*)(mislead + 15 + nop_amt), "\x8B\xE5\x5D", 3);
				tools::write_memory((void*)gadget, mislead, 23 + nop_amt);
				*(char*)(gadget + 18 + nop_amt) = 0xE9;
				*(UINT*)(gadget + 19 + nop_amt) = jump_to;

				VirtualProtect((LPVOID)gadget, 2, PAGE_EXECUTE_READ, &old_protect); // stuff like this pains me.

				gi = GadgetInfo(gadget, 24 + nop_amt);
			}

			if (!gi.created()) return;
			hooks[curr_index].gadget_chain.push_back(gi);
		};
		bool in_range(unsigned int address) {
			return (address >= min_safe_address && address <= max_safe_address);
		}
		void populate_acceptable_address_range() {
			MODULEINFO mi = { 0 };
			GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &mi, sizeof(MODULEINFO));

			min_safe_address = (uintptr_t)mi.lpBaseOfDll;
			max_safe_address = (uintptr_t)mi.lpBaseOfDll + mi.SizeOfImage;
		}
	private: // pv-member vars
		std::vector<HookInfo> hooks;
		const char* szModName;
		unsigned int our_func;
		unsigned int vmt_base_addy;
		unsigned int min_safe_address;
		unsigned int max_safe_address;
		int          curr_index;
};
