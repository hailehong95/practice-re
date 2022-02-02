#include <stdio.h>
#include <string.h>

// challenge!

int main(int argc, char const* argv[])
{
	if (argc <= 1) {
		printf("Usage: %s password\n", argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "s3kret!")) {
		printf("Congrats!");
	}

	return 0;
}