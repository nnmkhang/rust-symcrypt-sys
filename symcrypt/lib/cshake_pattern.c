//
// cshake_pattern.c
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


//
// This source file implements cSHAKE128 and cSHAKE256
//
// See the symcrypt.h file for documentation on what the various functions do.
//


//
// SymCryptCShake
//
VOID
SYMCRYPT_CALL
SYMCRYPT_Xxx(
    _In_reads_( cbFunctionNameString )  PCBYTE  pbFunctionNameString,
                                        SIZE_T  cbFunctionNameString,
    _In_reads_( cbCustomizationString ) PCBYTE  pbCustomizationString,
                                        SIZE_T  cbCustomizationString,
    _In_reads_( cbData )                PCBYTE  pbData,
                                        SIZE_T  cbData,
    _Out_writes_( cbResult )            PBYTE   pbResult,
                                        SIZE_T  cbResult)
{
    SYMCRYPT_XXX_STATE state;

    SYMCRYPT_XxxInit(&state, 
                    pbFunctionNameString, cbFunctionNameString, 
                    pbCustomizationString, cbCustomizationString);

    SYMCRYPT_XxxAppend(&state, pbData, cbData);
    SYMCRYPT_XxxExtract(&state, pbResult, cbResult, TRUE);
}


//
// SymCryptCShakeInit
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxInit(
    _Out_                               PSYMCRYPT_XXX_STATE pState,
    _In_reads_( cbFunctionNameString )  PCBYTE              pbFunctionNameString,
                                        SIZE_T              cbFunctionNameString,
    _In_reads_( cbCustomizationString ) PCBYTE              pbCustomizationString,
                                        SIZE_T              cbCustomizationString)
{
    SYMCRYPT_SHAKEXXX_INIT(pState);

    // Perform cSHAKE processing of input strings when any of the input strings is non-empty
    if (cbFunctionNameString != 0 || cbCustomizationString != 0)
    {
        // cSHAKE and SHAKE have different paddings. pState->paddingValue
        // is set to SYMCRYPT_SHAKE_PADDING_VALUE in the SHAKE initialization above.
        // We update the padding value here because at least one of the input strings
        // is non-empty and cSHAKE will not default to SHAKE.
        pState->paddingValue = SYMCRYPT_CSHAKE_PADDING_VALUE;

        SymCryptCShakeEncodeInputStrings(pState,
                                        pbFunctionNameString, cbFunctionNameString,
                                        pbCustomizationString, cbCustomizationString);
    }
}

//
// SymCryptCShakeAppend
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxAppend(
    _Inout_                 PSYMCRYPT_XXX_STATE pState,
    _In_reads_( cbData )    PCBYTE              pbData,
                            SIZE_T              cbData )
{
    // Fixing of the padding value
    // 
    // SymCryptKeccakAppend will reset the state, switch to absorb mode,
    // and append data to the empty state if the state was in squeeze mode 
    // when Append is called. This behavior is equivalent to initializing 
    // cSHAKE with empty input strings, which makes cSHAKE a SHAKE instance.
    //
    // cSHAKE and SHAKE have different paddings, so we have to update the 
    // padding value in case it was cSHAKE padding before.
    if (pState->squeezeMode)
    {
        pState->paddingValue = SYMCRYPT_SHAKE_PADDING_VALUE;
    }

    SymCryptKeccakAppend(pState, pbData, cbData);
}

//
// SymCryptCShakeExtract
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxExtract(
    _Inout_                 PSYMCRYPT_XXX_STATE pState,
    _Out_writes_(cbResult)  PBYTE               pbResult,
                            SIZE_T              cbResult,
                            BOOLEAN             bWipe)
{
    SymCryptKeccakExtract(pState, pbResult, cbResult, bWipe);

    if (bWipe)
    {
        // If the state was wiped, set the state as if cSHAKE was initialized 
        // with empty strings, which is equivalent to empty SHAKE state.
        // We have no way to store the Function Name string and Customization 
        // string information to go back to the initial cSHAKE state.
        pState->paddingValue = SYMCRYPT_SHAKE_PADDING_VALUE;
    }
}

//
// SymCryptCShakeResult
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxResult(
    _Inout_                                         PSYMCRYPT_XXX_STATE pState,
    _Out_writes_( SYMCRYPT_CSHAKEXXX_RESULT_SIZE )  PBYTE               pbResult)
{
    SymCryptKeccakExtract(pState, pbResult, SYMCRYPT_CSHAKEXXX_RESULT_SIZE, TRUE);

    // Revert to cSHAKE initialized with empty strings state, i.e., empty SHAKE state
    pState->paddingValue = SYMCRYPT_SHAKE_PADDING_VALUE;
}

//
// SymCryptCShakeStateCopy
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxStateCopy(_In_ const SYMCRYPT_XXX_STATE* pSrc, _Out_ SYMCRYPT_XXX_STATE* pDst)
{
    SYMCRYPT_CHECK_MAGIC(pSrc);
    *pDst = *pSrc;
    SYMCRYPT_SET_MAGIC(pDst);
}

# if 0
//
// SymCryptCShakeStateExport
//
VOID
SYMCRYPT_CALL
SYMCRYPT_XxxStateExport(
    _In_                                                        PCSYMCRYPT_XXX_STATE    pState,
    _Out_writes_bytes_(SYMCRYPT_CSHAKEXXX_STATE_EXPORT_SIZE)    PBYTE                   pbBlob)
{
    SymCryptKeccakStateExport(SYMCRYPT_BLOB_TYPE_XXX, pState, pbBlob);
}

//
// SymCryptCShakeStateImport
//
SYMCRYPT_ERROR
SYMCRYPT_CALL
SYMCRYPT_XxxStateImport(
    _Out_                                                   PSYMCRYPT_XXX_STATE pState,
    _In_reads_bytes_(SYMCRYPT_CSHAKEXXX_STATE_EXPORT_SIZE)  PCBYTE              pbBlob)
{
    return SymCryptKeccakStateImport(SYMCRYPT_BLOB_TYPE_XXX, pState, pbBlob);
}
#endif
