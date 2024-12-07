#include "tpm2_utils.c"

int main()
{
	system("mkdir tpm2");
	system("touch keys");
	tpm2_createprimary();
	tpm2_create();
	tpm2_load();
	tpm2_evictcontrol();
	tpm2_gen_iv();
	tpm2_encrypt();
	system("shred keys");
	system("rm keys");
}