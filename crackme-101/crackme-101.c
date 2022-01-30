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

int ValidationSerial(char* name, char* serial)
{
	int n = strlen(name);
	int num = 0;
	for (int i = 0; i < n; i++)
		num += (int)name[i];
	num ^= 0x5678;
	num ^= 0x1234;
	int rls = atoi(serial);
	if (rls == num)
		return 1;
	return 0;
}

int main()
{
	char strName[256], strSerial[256];

	printf("Enter Name: ");
	fgets(strName, sizeof(strName), stdin);
	strName[strlen(strName) - 1] = '\0';

	printf("Enter Serial: ");
	fgets(strSerial, sizeof(strSerial), stdin);
	strSerial[strlen(strSerial) - 1] = '\0';

	if (ValidationName(strName)) {
		if (ValidationSerial(strName, strSerial)) {
			printf("Great work, mate! Now try the next CrackMe!\n");
			return 101;
		}
	}
	printf("No luck there, mate!\n");

	return 0;
}