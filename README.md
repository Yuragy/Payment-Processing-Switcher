⚠️ ⚠️ ⚠️ We condemn any attempt to apply these mechanics, this repository was created for educational purposes for security research.

# Project structure
1. config
Contains configuration files and auxiliary utilities.
	- blk.dat: List of locked transactions in key-value format.
	- decryptJackpot.cpp: Utility to decrypt the created jackpot logs.
	- encrypt.cpp: Utility for encrypting used configuration data.
	- info.dat: List of PAN (Primary Account Number) numbers in key-value format.
	- info.ini: Configuration file containing data from info.dat and blk.dat, defining key operational parameters.

2. injector.

This directory contains injector code for the AIX/Linux and Windows platforms.
	- inAIX:
	- injectorAIX.cpp: An injector for AIX-based systems responsible for injecting XCOFF (shared object) into the target process.
	- makefile: A script to build the injector for AIX.
	- inWin:
	- injectorW.cpp: An injector for Windows, responsible for injecting a DLL into the target process.
	- makefile: Windows injector build script.

3. scr

Contains source code and libraries for handling ISO 8583 messages. It is divided into directories for AIX/Linux and Windows.
	- aix:
	- iso8583.cpp: Implementation of functions for working with ISO 8583.
	- iso8583.h: Header file with class and function declarations.
	- makefile: Script for building ISO 8583 processing code on AIX.
	- renaski1.1.cpp: Basic code for AIX that integrates with the injector.
	- win:
	- iso8583.cpp
	- iso8583.h
	- makefile
	- renaski1.0.cpp: Basic code for Windows that integrates with the injector.

Universal XCOFF/DLL configuration for processing servers and ATMs (AIX/Linux/Windows)
