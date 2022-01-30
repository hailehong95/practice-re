#pragma warning(disable:4996)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ValidationName(char* name)
{
	strupr(name);
	for (int i = 0; i < strlen(name); i++)
		if (name[i] < 'A' || name[i] > 'Z')
			return 0;
	return 1;
}

int CrackMe101Keygen(char* name)
{
	int n = strlen(name);
	int num = 0;
	for (int i = 0; i < n; i++)
		num += (int)name[i];
	num ^= 0x5678;
	num ^= 0x1234;
	return num;
}

int main()
{
	char strName[256];
	
	printf("Enter Name: ");
	fgets(strName, sizeof(strName), stdin);
	strName[strlen(strName) - 1] = '\0';

	if (ValidationName(strName)) {
		printf("Serial: %d\n", CrackMe101Keygen(strName));
		return 101;
	}

	printf("Invalid Name!\n");

	return 0;
}