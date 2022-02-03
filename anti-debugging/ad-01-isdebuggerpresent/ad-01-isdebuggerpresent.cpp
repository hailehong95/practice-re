#include <stdio.h>
#include <Windows.h>
#pragma comment (lib, "User32.Lib")
#pragma comment (linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

int main()
{
	if (IsDebuggerPresent()) {
		MessageBox(0, "Detect Debugging!", "IsDebuggerPresent", MB_OK);
		exit(-1);
	}

	MessageBox(0, "No Debugging!", "IsDebuggerPresent", MB_OK);

	return 0;
}