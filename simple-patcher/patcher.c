#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>

// patcher!

int main(int argc, char const* argv[])
{
	if (argc <= 1) {
		printf("Usage: %s target-bin\n", argv[0]);
		return 1;
	}

	// offset = 0x497, 0x498
	const char bytes[] = "\x90";
	FILE* f = fopen(argv[1], "r+b");

	for (long offset = 0x497; offset <= 0x498; offset++) {
		fseek(f, offset, SEEK_SET);
		fwrite((void*)bytes, 1, 1, f);
	}
	fclose(f);

	return 0;
}
