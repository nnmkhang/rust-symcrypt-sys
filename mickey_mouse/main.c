#include "symcrypt.h"

#include <stdio.h>



int main()
{

    const PSYMCRYPT_HASH test =  SymCryptSha384Algorithm; // code 
    const PSYMCRYPT_HASH test2 =  SymCryptSha256Algorithm; // data

    printf("hello");


    SymCryptHashStateSize(test); // this will AV, expected, can comment out to see expected 
    // functionality of the DATA export
    SymCryptHashStateSize(test2); // this will work, expected
    //printf("%s", result);
    return 0;
}


