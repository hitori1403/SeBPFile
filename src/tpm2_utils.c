#include <stdio.h>
#include <stdlib.h>

void tpm2_createprimary()
{
	system("/usr/bin/tpm2_createprimary -Q -c tpm2/primary.ctx");
}

void tpm2_create()
{
	system("/usr/bin/tpm2_create -Q -C tpm2/primary.ctx -G aes128 -u tpm2/key.pub -r tpm2/key.priv");
}

void tpm2_gen_iv()
{
	system("/usr/bin/tpm2_getrandom 16 -o tpm2/iv");
}

void tpm2_load()
{
	system("/usr/bin/tpm2_load -Q -C tpm2/primary.ctx -u tpm2/key.pub -r tpm2/key.priv -c tpm2/key.ctx");
}

void tpm2_encrypt()
{
	system("/usr/bin/tpm2_encryptdecrypt -Q -c 0x81008742 -t tpm2/iv -o keys.enc keys");
}

void tpm2_decrypt()
{
	system("/usr/bin/tpm2_encryptdecrypt -Q -d -c 0x81008742 -t tpm2/iv -o keys keys.enc");
}

void tpm2_evictcontrol()
{
	system("/usr/bin/tpm2_evictcontrol -Q -c tpm2/key.ctx 0x81008742");
}

// int main()
// {
// 	createprimary();
// 	create();
// 	load();
// 	gen_iv();
// 	encrypt();
// 	decrypt();
// }