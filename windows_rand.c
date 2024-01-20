#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include "windows_rand.h"


/*This function return a random number from 0 to 2^32-1 
  in defined range from 0(min) to 2^32-1(max) */
unsigned win_rand(unsigned min_range, unsigned max_range)
{
	const int RND_HEX_STRING_SIZE = 4;
	HCRYPTPROV hCryptProv;
	BYTE* pbData = (BYTE*)malloc(sizeof(BYTE)* RND_HEX_STRING_SIZE);
	if (CryptAcquireContext(
		&hCryptProv,
		NULL,
		(LPCWSTR)L"Microsoft Base Cryptographic Provider v1.0",
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		if (CryptGenRandom(
			hCryptProv,
			RND_HEX_STRING_SIZE,
			pbData))
		{
			if (CryptReleaseContext(hCryptProv, 0))
			{
				unsigned rnd_num = 0;
				for (int i = 0; i < 4; i++) {
					rnd_num <<= 8;
					rnd_num |= pbData[i];
					//printf("pbData[%d] = %02X\n", i, pbData[i]);
				}
				//printf("rnd_num =%u(%08X)\n", rnd_num, rnd_num);

				return min_range + (rnd_num % (max_range-min_range));
			}
			else
			{
				printf("Error during CryptReleaseContext.\n");
				return -4;
			}
		}
		else
		{
			if (CryptReleaseContext(hCryptProv, 0))
			{
				printf("Error during CryptGenRandom.\n");
				return -2;
			}
			else
			{
				printf("Error during CryptReleaseContext.\n");
				return -3;
			}
		}
	}
	else
	{
		printf("Error during CryptAcquireContext!\n");
		return -1;
	}
}
