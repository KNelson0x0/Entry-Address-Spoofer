#pragma once
namespace hooks {
	struct printHello {
		using Fn = void __fastcall(void*);
		static Fn hooked;
		static Fn* original;
	};
};