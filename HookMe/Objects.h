#pragma once
#include <iostream>
class BaseObject {
public:
	BaseObject() {};
	virtual void printHello() {
		std::cout << "Hello\n";
	}
	virtual void printGoodbye() {
		std::cout << "Goodbye\n";
	}
	virtual void printHouse() {
		std::cout << "House\n ";
	}
	virtual void printILoveFillerFuncs() {
		std::cout << "I Love Filler Funcs\n ";
	}
	virtual void printAVThatAnnoysMe() {
		std::cout << "Norton\n";
	}
};

class InheritingObject : public BaseObject {
public:
	InheritingObject() {};
	void printWord(const char* word) {
		std::cout << word << "\n";
	}
};