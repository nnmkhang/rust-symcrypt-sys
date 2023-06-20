;
;  AesAsm.asm   Assembler code for fast AES on ARM
;
; Copyright (c) Microsoft Corporation. Licensed under the MIT license.
;
; This code is derived from the AMD64 version of the AesFast
; implementation, developed by Niels Ferguson. For questions
; about the ARM specifics, contact Aaron Giles.
;

#include "kxarm.h"

; As Arm assembler already uses C preprocessor, we can just hardcode this asm to include constants
; MASM for now. To be fixed properly when converting arm64 asm to symcryptasm.
#define SYMCRYPT_MASM
#include "C_asm_shared.inc"
#undef SYMCRYPT_MASM

#include "symcrypt_magic.inc"

        TTL   "Advanced Encryption Standard (AES)"

;
; typedef SYMCRYPT_ALIGN_STRUCT _SYMCRYPT_AES_EXPANDED_KEY {
;     SYMCRYPT_ALIGN BYTE RoundKey[29][4][4];
;         // Round keys, first the encryption round keys in encryption order,
;         // followed by the decryption round keys in decryption order.
;         // The first decryption round key is the last encryption round key.
;         // AES-256 has 14 rounds and thus 15 round keys for encryption and 15
;         // for decryption. As they share one round key, we need room for 29.
;     BYTE   (*lastEncRoundKey)[4][4];    // Pointer to last encryption round key
;                                         // also the first round key for decryption
;     BYTE   (*lastDecRoundKey)[4][4];    // Pointer to last decryption round key.
;
;     SYMCRYPT_MAGIC_FIELD
; } SYMCRYPT_AES_EXPANDED_KEY, *PSYMCRYPT_AES_EXPANDED_KEY;
;

#define SYMCRYPT_AES_EXPANDED_KEY_RoundKey          (0)
#define SYMCRYPT_AES_EXPANDED_KEY_lastEncRoundKey   (29*4*4)
#define SYMCRYPT_AES_EXPANDED_KEY_lastDecRoundKey   (29*4*4+4)

#if SYMCRYPT_DEBUG
#define SYMCRYPT_AES_EXPANDED_KEY_magic             (29*4*4+4+4)
#endif


        IMPORT  SymCryptAesSboxMatrixMult
        IMPORT  SymCryptAesInvSboxMatrixMult
        IMPORT  SymCryptAesInvSbox


        MACRO
        ENC_MIX $keyptr

        ;
        ; Perform the unkeyed mixing function for encryption
        ; plus a key addition from the key pointer
        ;
        ; Input:
        ;   r0,r1,r2,r3 = current block
        ;   $keyptr = pointer to current key
        ;   r12 = pointer to AesSboxMatrixMult
        ;
        ; Output:
        ;   r0,r1,r2,r3 = updated block
        ;   $keyptr = updated to point to following key
        ;   r12 = unmodified
        ;
        ; Used:
        ;   r4,r5,r6,r7,lr are modified
        ;
        ; N.B. To make better use of ARM's barrel shifter, this code differs
        ;      from the AMD64 approach. The first lookups are not rotated;
        ;      instead all subsequent lookups are applied on top rotated, and
        ;      then a final rotation is performed to shift the bits into the
        ;      proper spot.
        ;

        uxtb    r4, r0                          ; extract individual bytes from r0
        uxtb    r7, r0, ror #8                  ;
        uxtb    r6, r0, ror #16                 ;
        uxtb    r5, r0, ror #24                 ;
        ldr     r4, [r12, r4, lsl #2]           ; perform lookups of each byte, leaving
        ldr     r7, [r12, r7, lsl #2]           ;   the values unrotated for now
        ldr     r6, [r12, r6, lsl #2]           ;
        ldr     r5, [r12, r5, lsl #2]           ;

        uxtb    r0, r1                          ; extract individual bytes from r1
        uxtb    lr, r1, ror #8                  ;   (with 1 more register we could do 4 at a time)
        ldr     r0, [r12, r0, lsl #2]           ; perform lookups
        ldr     lr, [r12, lr, lsl #2]           ;
        eor     r5, r5, r0, ror #24             ; exclusive-OR with previous
        eor     r4, r4, lr, ror #24             ;
        uxtb    r0, r1, ror #16                 ; extract remaining bytes from r1
        uxtb    r1, r1, ror #24                 ;
        ldr     r0, [r12, r0, lsl #2]           ; perform lookups
        ldr     r1, [r12, r1, lsl #2]           ;
        eor     r7, r7, r0, ror #24             ; exclusive-OR with previous
        eor     r6, r6, r1, ror #24             ;

        uxtb    r0, r2                          ; extract individual bytes from r2
        uxtb    r1, r2, ror #8                  ;
        uxtb    lr, r2, ror #16                 ;
        uxtb    r2, r2, ror #24                 ;
        ldr     r0, [r12, r0, lsl #2]           ; perform lookups
        ldr     r1, [r12, r1, lsl #2]           ;
        ldr     lr, [r12, lr, lsl #2]           ;
        ldr     r2, [r12, r2, lsl #2]           ;
        eor     r6, r6, r0, ror #16             ; exclusive-OR with previous
        eor     r5, r5, r1, ror #16             ;
        eor     r4, r4, lr, ror #16             ;
        eor     r7, r7, r2, ror #16             ;

        uxtb    r0, r3                          ; extract individual bytes from r3
        uxtb    r1, r3, ror #8                  ;
        uxtb    r2, r3, ror #16                 ;
        uxtb    r3, r3, ror #24                 ;
        ldr     r0, [r12, r0, lsl #2]           ; perform lookups
        ldr     r1, [r12, r1, lsl #2]           ;
        ldr     r2, [r12, r2, lsl #2]           ;
        ldr     r3, [r12, r3, lsl #2]           ;
        eor     r7, r7, r0, ror #8              ; exclusive-OR with previous
        eor     r6, r6, r1, ror #8              ;
        eor     r5, r5, r2, ror #8              ;
        eor     r4, r4, r3, ror #8              ;

        ldrd    r0, r1, [$keyptr, #0]           ; fetch key into r0-r3
        ldrd    r2, r3, [$keyptr, #8]           ;
        adds    $keyptr, $keyptr, #16           ; increment key pointer
        eors    r0, r0, r4                      ; exclusive-OR the key and rotate into final
        eor     r1, r1, r5, ror #8              ;   position
        eor     r2, r2, r6, ror #16             ;
        eor     r3, r3, r7, ror #24             ;
        MEND


        MACRO
        DEC_MIX $keyptr

        ;
        ; Perform the unkeyed mixing function for decryption
        ;
        ; Input:
        ;   r0,r1,r2,r3 = current block
        ;   $keyptr = pointer to current key
        ;   r12 = pointer to AesInvSboxMatrixMult
        ;
        ; Output:
        ;   r0,r1,r2,r3 = updated block
        ;   $keyptr = updated to point to following key
        ;   r12 = unmodified
        ;
        ; Used:
        ;   r4,r5,r6,r7,lr are modified
        ;
        ; N.B. To make better use of ARM's barrel shifter, this code differs
        ;      from the AMD64 approach. The first lookups are not rotated;
        ;      instead all subsequent lookups are applied on top rotated, and
        ;      then a final rotation is performed to shift the bits into the
        ;      proper spot.
        ;

        uxtb    r4, r0                          ; extract individual bytes from r0
        uxtb    r5, r0, ror #8                  ;
        uxtb    r6, r0, ror #16                 ;
        uxtb    r7, r0, ror #24                 ;
        ldr     r4, [r12, r4, lsl #2]           ; perform lookups of each byte, leaving
        ldr     r5, [r12, r5, lsl #2]           ;   the values unrotated for now
        ldr     r6, [r12, r6, lsl #2]           ;
        ldr     r7, [r12, r7, lsl #2]           ;

        uxtb    r0, r1                          ; extract individual bytes from r1
        uxtb    lr, r1, ror #8                  ;   (with 1 more register we could do 4 at a time)
        ldr     r0, [r12, r0, lsl #2]           ; perform lookups
        ldr     lr, [r12, lr, lsl #2]           ;
        eor     r5, r5, r0, ror #8              ; exclusive-OR with previous
        eor     r6, r6, lr, ror #8              ;
        uxtb    r0, r1, ror #16                 ; extract remaining bytes from r1
        uxtb    r1, r1, ror #24                 ;
        ldr     r0, [r12, r0, lsl #2]           ; perform lookups
        ldr     r1, [r12, r1, lsl #2]           ;
        eor     r7, r7, r0, ror #8              ; exclusive-OR with previous
        eor     r4, r4, r1, ror #8              ;

        uxtb    r0, r2                          ; extract individual bytes from r2
        uxtb    r1, r2, ror #8                  ;
        uxtb    lr, r2, ror #16                 ;
        uxtb    r2, r2, ror #24                 ;
        ldr     r0, [r12, r0, lsl #2]           ; perform lookups
        ldr     r1, [r12, r1, lsl #2]           ;
        ldr     lr, [r12, lr, lsl #2]           ;
        ldr     r2, [r12, r2, lsl #2]           ;
        eor     r6, r6, r0, ror #16             ; exclusive-OR with previous
        eor     r7, r7, r1, ror #16             ;
        eor     r4, r4, lr, ror #16             ;
        eor     r5, r5, r2, ror #16             ;

        uxtb    r0, r3                          ; extract individual bytes from r3
        uxtb    r1, r3, ror #8                  ;
        uxtb    r2, r3, ror #16                 ;
        uxtb    r3, r3, ror #24                 ;
        ldr     r0, [r12, r0, lsl #2]           ; perform lookups
        ldr     r1, [r12, r1, lsl #2]           ;
        ldr     r2, [r12, r2, lsl #2]           ;
        ldr     r3, [r12, r3, lsl #2]           ;
        eor     r7, r7, r0, ror #24             ; exclusive-OR with previous
        eor     r4, r4, r1, ror #24             ;
        eor     r5, r5, r2, ror #24             ;
        eor     r6, r6, r3, ror #24             ;

        ldrd    r0, r1, [$keyptr, #0]           ; fetch key into r0-r3
        ldrd    r2, r3, [$keyptr, #8]           ;
        adds    $keyptr, $keyptr, #16           ; increment key pointer
        eors    r0, r0, r4                      ; exclusive-OR the key and rotate into final
        eor     r1, r1, r5, ror #24             ;   position
        eor     r2, r2, r6, ror #16             ;
        eor     r3, r3, r7, ror #8              ;

        MEND



        MACRO
        AES_ENCRYPT

        ;
        ; Input:
        ;   r0,r1,r2,r3 = plaintext
        ;   r8 = pointer to first round key to use
        ;   r9 = pointer to last key to use
        ;   r12 = pointer to AesSboxMatrixMult
        ;
        ; Output:
        ;   r4,r5,r6,r7 = ciphertext
        ;   r8 = modified to point to last key
        ;   r9 = unmodified
        ;   r12 = unmodified
        ;
        ; Used:
        ;   lr is also modified
        ;

        ;
        ; xor in first round key
        ;

        ldrd    r4, r5, [r8, #0]                ; fetch key in r4-r7
        ldrd    r6, r7, [r8, #8]                ;
        eors    r0, r0, r4                      ; exclusive-OR with the plaintext
        eors    r1, r1, r5                      ;
        eors    r2, r2, r6                      ;
        eors    r3, r3, r7                      ;

        add     r8, r8, #16                     ; point to second key

1
        ;
        ; Block is r0,r1,r2,r3
        ; r8 points to current round key
        ;

        ENC_MIX r8                              ; encrypt the block and increment key
        cmp     r8, r9                          ; are we at the end?
        blo     %B1                             ; loop until it is so

        ;
        ; Now for the final round
        ; We use the fact that SboxMatrixMult[0] table is also
        ; an Sbox table if you use the second element of each entry.
        ;
        ; Result is in r4,r5,r6,r7
        ;

        add     r12, r12, #1                    ; advance by 1 to point to second element
        uxtb    r4, r0                          ; extract individual bytes from r0
        uxtb    r7, r0, ror #8                  ;
        uxtb    r6, r0, ror #16                 ;
        uxtb    r5, r0, ror #24                 ;
        ldrb    r4, [r12, r4, lsl #2]           ; perform lookups of each byte, leaving
        ldrb    r7, [r12, r7, lsl #2]           ;   the values unrotated for now
        ldrb    r6, [r12, r6, lsl #2]           ;
        ldrb    r5, [r12, r5, lsl #2]           ;

        uxtb    r0, r1                          ; extract individual bytes from r1
        uxtb    lr, r1, ror #8                  ;   (with 1 more register we could do 4 at a time)
        ldrb    r0, [r12, r0, lsl #2]           ; perform lookups
        ldrb    lr, [r12, lr, lsl #2]           ;
        orr     r5, r5, r0, lsl #8              ; merge with previous
        orr     r4, r4, lr, lsl #8              ;
        uxtb    r0, r1, ror #16                 ; extract remaining bytes from r1
        uxtb    r1, r1, ror #24                 ;
        ldrb    r0, [r12, r0, lsl #2]           ; perform lookups
        ldrb    r1, [r12, r1, lsl #2]           ;
        orr     r7, r7, r0, lsl #8              ; merge with previous
        orr     r6, r6, r1, lsl #8              ;

        uxtb    r0, r2                          ; extract individual bytes from r2
        uxtb    r1, r2, ror #8                  ;
        uxtb    lr, r2, ror #16                 ;
        uxtb    r2, r2, ror #24                 ;
        ldrb    r0, [r12, r0, lsl #2]           ; perform lookups
        ldrb    r1, [r12, r1, lsl #2]           ;
        ldrb    lr, [r12, lr, lsl #2]           ;
        ldrb    r2, [r12, r2, lsl #2]           ;
        orr     r6, r6, r0, lsl #16             ; merge with previous
        orr     r5, r5, r1, lsl #16             ;
        orr     r4, r4, lr, lsl #16             ;
        orr     r7, r7, r2, lsl #16             ;

        uxtb    r0, r3                          ; extract individual bytes from r3
        uxtb    r1, r3, ror #8                  ;
        uxtb    r2, r3, ror #16                 ;
        uxtb    r3, r3, ror #24                 ;
        ldrb    r0, [r12, r0, lsl #2]           ; perform lookups
        ldrb    r1, [r12, r1, lsl #2]           ;
        ldrb    r2, [r12, r2, lsl #2]           ;
        ldrb    r3, [r12, r3, lsl #2]           ;
        orr     r7, r7, r0, lsl #24             ; merge with previous
        orr     r6, r6, r1, lsl #24             ;
        orr     r5, r5, r2, lsl #24             ;
        orr     r4, r4, r3, lsl #24             ;
        sub     r12, r12, #1                    ; put r12 back to its original value

        ;
        ; xor in final round key
        ;

        ldrd    r0, r1, [r9, #0]                ; fetch key into r0-r3
        ldrd    r2, r3, [r9, #8]                ;
        eors    r4, r4, r0                      ; exclusive-OR the key and rotate into final
        eor     r5, r1, r5, ror #8              ;   position
        eor     r6, r2, r6, ror #16             ;
        eor     r7, r3, r7, ror #24             ;

        MEND


        MACRO
        AES_DECRYPT

        ;
        ; Input:
        ;   r0,r1,r2,r3 = ciphertext
        ;   r8 = pointer to first round key to use
        ;   r9 = pointer to last key to use
        ;   r10 = pointer to InvSbox
        ;   r12 = pointer to InvSboxMatrixMult
        ;
        ; Output:
        ;   r4,r5,r6,r7 = plaintext
        ;   r8 = modified to point to last key
        ;   r9 = unmodified
        ;   r10 = unmodified
        ;   r12 = unmodified
        ;
        ; Used:
        ;   lr is also modified
        ;

        ;
        ; xor in first round key
        ;
        ldrd    r4, r5, [r8, #0]                ; fetch key in r4-r7
        ldrd    r6, r7, [r8, #8]                ;
        eors    r0, r0, r4                      ; exclusive-OR with the plaintext
        eors    r1, r1, r5                      ;
        eors    r2, r2, r6                      ;
        eors    r3, r3, r7                      ;

        add     r8, r8, #16                     ; point to second key

1
        ;
        ; Block is r0, r1, r2, r3
        ; r8 points to current round key
        ;

        DEC_MIX r8                              ; decrypt the block and increment key
        cmp     r8, r9                          ; are we at the end?
        blo     %B1                             ; loop until it is so

        ;
        ; Now for the final round
        ; Result is in r4, r5, r6, r7
        ;

        uxtb    r4, r0                          ; extract individual bytes from r0
        uxtb    r5, r0, ror #8                  ;
        uxtb    r6, r0, ror #16                 ;
        uxtb    r7, r0, ror #24                 ;
        ldrb    r4, [r10, r4]                   ; perform lookups of each byte, leaving
        ldrb    r5, [r10, r5]                   ;   the values unrotated for now
        ldrb    r6, [r10, r6]                   ;
        ldrb    r7, [r10, r7]                   ;

        uxtb    r0, r1                          ; extract individual bytes from r1
        uxtb    lr, r1, ror #8                  ;   (with 1 more register we could do 4 at a time)
        ldrb    r0, [r10, r0]                   ; perform lookups
        ldrb    lr, [r10, lr]                   ;
        orr     r5, r5, r0, lsl #24             ; merge with previous
        orr     r6, r6, lr, lsl #24             ;
        uxtb    r0, r1, ror #16                 ; extract remaining bytes from r1
        uxtb    r1, r1, ror #24                 ;
        ldrb    r0, [r10, r0]                   ; perform lookups
        ldrb    r1, [r10, r1]                   ;
        orr     r7, r7, r0, lsl #24             ; merge with previous
        orr     r4, r4, r1, lsl #24             ;

        uxtb    r0, r2                          ; extract individual bytes from r2
        uxtb    r1, r2, ror #8                  ;
        uxtb    lr, r2, ror #16                 ;
        uxtb    r2, r2, ror #24                 ;
        ldrb    r0, [r10, r0]                   ; perform lookups
        ldrb    r1, [r10, r1]                   ;
        ldrb    lr, [r10, lr]                   ;
        ldrb    r2, [r10, r2]                   ;
        orrs    r6, r6, r0, lsl #16             ; merge with previous
        orr     r7, r7, r1, lsl #16             ;
        orr     r4, r4, lr, lsl #16             ;
        orr     r5, r5, r2, lsl #16             ;

        uxtb    r0, r3                          ; extract individual bytes from r3
        uxtb    r1, r3, ror #8                  ;
        uxtb    r2, r3, ror #16                 ;
        uxtb    r3, r3, ror #24                 ;
        ldrb    r0, [r10, r0]                   ; perform lookups
        ldrb    r1, [r10, r1]                   ;
        ldrb    r2, [r10, r2]                   ;
        ldrb    r3, [r10, r3]                   ;
        orr     r7, r7, r0, lsl #8              ; merge with previous
        orr     r4, r4, r1, lsl #8              ;
        orr     r5, r5, r2, lsl #8              ;
        orr     r6, r6, r3, lsl #8              ;

        ;
        ; xor in final round key
        ;

        ldrd    r0, r1, [r9, #0]                ; fetch key into r0-r3
        ldrd    r2, r3, [r9, #8]                ;
        eors    r4, r4, r0                      ; exclusive-OR the key and rotate into final
        eor     r5, r1, r5, ror #24             ;   position
        eor     r6, r2, r6, ror #16             ;
        eor     r7, r3, r7, ror #8              ;

        MEND


;
; VOID
; SYMCRYPT_CALL
; SymCryptAesEncrypt( _In_                                         PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
;                     _In_reads_bytes_( SYMCRYPT_AES_BLOCK_LEN )   PCBYTE                      pbPlaintext,
;                     _Out_writes_bytes_( SYMCRYPT_AES_BLOCK_LEN ) PBYTE                       pbCiphertext );
;

        NESTED_ENTRY    SymCryptAesEncryptAsm

        ;
        ; Input parameters:
        ;   r0 = pExpandedKey
        ;   r1 = pbPlaintext
        ;   r2 = pbCiphertext
        ;

        PROLOG_PUSH {r2, r4-r11, lr}

        ;
        ; Stack layout:
        ;   [sp] = r2 = pbCipherText
        ;

        SYMCRYPT_CHECK_MAGIC r4, r5, r0, SYMCRYPT_AES_EXPANDED_KEY_magic

        ldr     r9, [r0, #SYMCRYPT_AES_EXPANDED_KEY_lastEncRoundKey] ; r9 = last key
        mov     r8, r0                          ; r8 = first key
        mov32   r12, SymCryptAesSboxMatrixMult  ; r12 = matrix mult table

        ldr     r0, [r1, #0]                    ; load the plaintext
        ldr     r2, [r1, #8]                    ;
        ldr     r3, [r1, #12]                   ;
        ldr     r1, [r1, #4]                    ;

        AES_ENCRYPT                             ; encrypt
        ;
        ; Plaintext in r0, r1, r2, r3
        ; r8 points to first round key to use
        ; r9 is last key to use (unchanged)
        ; r12 points to SboxMatrixMult (unchanged)
        ; Ciphertext ends up in r4, r5, r6, r7
        ;

        ldr     r0, [sp]                        ; recover pbCipherText
        str     r4, [r0, #0]                    ; store the encrypted data
        str     r5, [r0, #4]                    ;
        str     r6, [r0, #8]                    ;
        str     r7, [r0, #12]                   ;

        EPILOG_POP {r2, r4-r11, pc}             ; return

        NESTED_END      SymCryptAesEncryptAsm


;
; VOID
; SYMCRYPT_CALL
; SymCryptAesDecrypt( _In_                                         PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
;                     _In_reads_bytes_( SYMCRYPT_AES_BLOCK_LEN )   PCBYTE                      pbCiphertext,
;                     _Out_writes_bytes_( SYMCRYPT_AES_BLOCK_LEN ) PBYTE                       pbPlaintext );
;

        NESTED_ENTRY    SymCryptAesDecryptAsm

        ;
        ; Input parameters:
        ;   r0 = pExpandedKey
        ;   r1 = pbCiphertext
        ;   r2 = pbPlaintext
        ;

        PROLOG_PUSH {r2, r4-r11, lr}

        ;
        ; Stack layout:
        ;   [sp] = r2 = pbPlaintext
        ;

        SYMCRYPT_CHECK_MAGIC r4, r5, r0, SYMCRYPT_AES_EXPANDED_KEY_magic

        ldr     r8, [r0, #SYMCRYPT_AES_EXPANDED_KEY_lastEncRoundKey] ; r8 = first key
        ldr     r9, [r0, #SYMCRYPT_AES_EXPANDED_KEY_lastDecRoundKey] ; r9 = last key
        mov32   r10, SymCryptAesInvSbox         ; r10 = inverse sbox table
        mov32   r12, SymCryptAesInvSboxMatrixMult ; r11 = inverse matrix mult table

        ldr     r0, [r1, #0]                    ; load the ciphertext
        ldr     r2, [r1, #8]                    ;
        ldr     r3, [r1, #12]                   ;
        ldr     r1, [r1, #4]                    ;

        AES_DECRYPT                             ; decrypt
        ;
        ; Ciphertext in r0, r1, r2, r3
        ; r8 points to first round key to use
        ; r9 is last key to use (unchanged)
        ; r10 points to InvSbox (unchanged)
        ; r12 points to InvSboxMatrixMult (unchanged)
        ; Ciphertext ends up in r4, r5, r6, r7
        ;

        ldr     r0, [sp]                        ; recover pbPlaintext
        str     r4, [r0, #0]                    ; store the decrypted data
        str     r5, [r0, #4]                    ;
        str     r6, [r0, #8]                    ;
        str     r7, [r0, #12]                   ;

        EPILOG_POP {r2, r4-r11, pc}             ; return

        NESTED_END      SymCryptAesDecryptAsm


;
; VOID
; SYMCRYPT_CALL
; SymCryptAesCbcEncrypt(
;     _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
;     _In_reads_bytes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbChainingValue,
;     _In_reads_bytes_( cbData )                  PCBYTE                      pbSrc,
;     _Out_writes_bytes_( cbData )                PBYTE                       pbDst,
;                                                 SIZE_T                      cbData );

        NESTED_ENTRY    SymCryptAesCbcEncryptAsm

        ;
        ; Input parameters:
        ;   r0 = pExpandedKey
        ;   r1 = pbChainingValue
        ;   r2 = pbSrc
        ;   r3 = pbDst
        ;   [sp] = cbData
        ;

        PROLOG_PUSH {r0-r2, r4-r11, lr}
        PROLOG_STACK_ALLOC 16

        ;
        ; Stack layout:
        ;   [sp] = pbSrc
        ;   [sp+4] = pbSrcEnd
        ;   [sp+16] = r0 = pbExpandedKey
        ;   [sp+20] = r1 = pbChainingValue
        ;   [sp+24] = r2 = pbSrc
        ;   [sp+64] = cbData
        ;

        SYMCRYPT_CHECK_MAGIC r4, r5, r0, SYMCRYPT_AES_EXPANDED_KEY_magic

        pld     [r2]                    ; prefetch source data
        ldr     r4, [sp, #64]           ; r4 = cbData
        mov     r8, r2                  ; r8 = pbSrc on loop entry
        ldr     r9, [r0, #SYMCRYPT_AES_EXPANDED_KEY_lastEncRoundKey] ; r9 = last enc round key (invariant)
        mov     r10, r3                 ; r10 = pbDst
        mov32   r12, SymCryptAesSboxMatrixMult ; r12 = pointer to lookup table (invariant)
        bics    r4, r4, #15             ; r4 &= ~15
        beq     SymCryptAesCbcEncryptNoData ; skip if no data
        adds    r4, r4, r2              ; r4 = pbSrc + cbData
        strd    r2, r4, [sp]            ; save pbSrc/pbSrcEnd at [sp]

        pld     [r8, #32]               ; prefetch source data
        ldr     r4, [r1, #0]            ; load chaining state from pbChainingValue
        ldr     r5, [r1, #4]            ;
        ldr     r6, [r1, #8]            ;
        ldr     r7, [r1, #12]           ;

SymCryptAesCbcEncryptAsmLoop
        ;
        ; Loop register setup
        ;   r4,r5,r6,r7 = chaining state
        ;   r8 = pbSrc
        ;   r9 = last round key to use
        ;   r10 = pbDst
        ;   r12 = SboxMatrixMult
        ;

        ldr     r0, [r8]                ; read next 16 bytes of plaintext
        ldr     r1, [r8, #4]            ;
        ldr     r2, [r8, #8]            ;
        ldr     r3, [r8, #12]           ;
        pld     [r8, #64]               ; prefetch source data
        add     r8, r8, #16             ; pbSrc += 16
        str     r8, [sp]                ; save it

        eors    r0, r0, r4              ; exclusive-OR against chaining value
        eors    r1, r1, r5              ;
        eors    r2, r2, r6              ;
        eors    r3, r3, r7              ;

        ldr     r8, [sp, #16]           ; r8 = first round key
        AES_ENCRYPT                     ; encrypt
        ;
        ; Plaintext in r0, r1, r2, r3
        ; r8 points to first round key to use
        ; r9 is last key to use (unchanged)
        ; r12 points to SboxMatrixMult (unchanged)
        ; Ciphertext ends up in r4, r5, r6, r7
        ;

        ldrd    r8, r0, [sp]            ; fetch pbSrc/pbSrcEnd

        str     r4, [r10, #0]           ; write ciphertext
        str     r5, [r10, #4]           ;
        str     r6, [r10, #8]           ;
        str     r7, [r10, #12]          ;
        add     r10, r10, #16           ; pbDst += 16

        cmp     r8, r0                  ; are we at the end of source?
        blo     SymCryptAesCbcEncryptAsmLoop ; loop until we are

        ldr     r0, [sp, #20]           ; r0 = pbChainingValue
        str     r4, [r0, #0]            ; update the chaining value
        str     r5, [r0, #4]            ;
        str     r6, [r0, #8]            ;
        str     r7, [r0, #12]           ;

SymCryptAesCbcEncryptNoData

        EPILOG_STACK_FREE 16
        EPILOG_POP {r0-r2, r4-r11, pc}  ; return

        NESTED_END      SymCryptAesCbcEncryptAsm


;
; VOID
; SYMCRYPT_CALL
; SymCryptAesCbcDecrypt(
;     _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
;     _In_reads_bytes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbChainingValue,
;     _In_reads_bytes_( cbData )                  PCBYTE                      pbSrc,
;     _Out_writes_bytes_( cbData )                PBYTE                       pbDst,
;                                                 SIZE_T                      cbData );

        NESTED_ENTRY    SymCryptAesCbcDecryptAsm

        ;
        ; Input parameters:
        ;   r0 = pExpandedKey
        ;   r1 = pbChainingValue
        ;   r2 = pbSrc
        ;   r3 = pbDst
        ;   [sp] = cbData
        ;

        PROLOG_PUSH {r0-r2, r4-r11, lr}
        PROLOG_STACK_ALLOC 32

        ;
        ; Stack layout:
        ;   [sp] = pbSrc
        ;   [sp+4] = pbDst
        ;   [sp+8] = pbSrcEnd
        ;   [sp+16] = saved chaining value
        ;   [sp+32] = r0 = pbExpandedKey
        ;   [sp+36] = r1 = pbChainingValue
        ;   [sp+40] = r2 = pbSrc
        ;   [sp+80] = cbData
        ;

        SYMCRYPT_CHECK_MAGIC r4, r5, r0, SYMCRYPT_AES_EXPANDED_KEY_magic

        ldr     r4, [sp, #80]           ; r4 = cbData
        bics    r4, r4, #15             ; r4 &= ~15
        beq     SymCryptAesCbcDecryptNoData ; skip if no data

        ldr     r9, [r0, #SYMCRYPT_AES_EXPANDED_KEY_lastDecRoundKey] ; r9 = last enc round key (invariant)
        ldr     r8, [r0, #SYMCRYPT_AES_EXPANDED_KEY_lastEncRoundKey]

        subs    r4, r4, #16
        adds    r3, r3, r4
        adds    r2, r2, r4
        pld     [r2]                    ; prefetch source data
        str     r3, [sp, #4]
        str     r2, [sp, #0]
        str     r8, [sp, #8]

        mov32   r10, SymCryptAesInvSbox
        mov32   r12, SymCryptAesInvSboxMatrixMult

        ;
        ; Load last ciphertext block & save on stack (we need to put it in the pbChaining buffer later)
        ;
        pld     [r2, #-32]              ; prefetch source data
        ldr     r0, [r2, #0]
        ldr     r1, [r2, #4]
        ldr     r3, [r2, #12]
        ldr     r2, [r2, #8]

        strd    r0, r1, [sp, #16]
        strd    r2, r3, [sp, #24]

        b       SymCryptAesCbcDecryptAsmLoopEntry

SymCryptAesCbcDecryptAsmLoop
        ; Loop register setup
        ; r13 = first round key to use
        ; r14 = pbSrc
        ; r15 = pbDst
        ; [callerP3Home] = pbSrcStart

        ; current ciphertext block (esi,edi,ebp,r8d)

        ldr     r0, [r8, #-16]
        ldr     r1, [r8, #-12]
        ldr     r2, [r8, #-8]
        ldr     r3, [r8, #-4]
        pld     [r8, #-64]              ; prefetch source data

        eors    r4, r4, r0
        eors    r5, r5, r1
        eors    r6, r6, r2
        eors    r7, r7, r3

        str     r4, [lr, #0]
        str     r5, [lr, #4]
        str     r6, [lr, #8]
        str     r7, [lr, #12]

        sub     lr, lr, #16
        sub     r8, r8, #16
        strd    r8, lr, [sp, #0]

SymCryptAesCbcDecryptAsmLoopEntry

        ldr     r8, [sp, #8]

        AES_DECRYPT

        ldrd    r8, lr, [sp, #0]
        ldr     r0, [sp, #40]
        cmp     r8, r0
        bhi     SymCryptAesCbcDecryptAsmLoop

        ldr     r8, [sp, #36]           ; r8 = pbChainingValue
        ldr     r0, [r8, #0]
        ldr     r1, [r8, #4]
        ldr     r2, [r8, #8]
        ldr     r3, [r8, #12]

        eors    r4, r4, r0
        eors    r5, r5, r1
        eors    r6, r6, r2
        eors    r7, r7, r3

        str     r4, [lr, #0]
        str     r5, [lr, #4]
        str     r6, [lr, #8]
        str     r7, [lr, #12]

        ;
        ; Update the chaining value to the last ciphertext block
        ;
        ldrd    r0, r1, [sp, #16]
        ldrd    r2, r3, [sp, #24]
        str     r0, [r8, #0]
        str     r1, [r8, #4]
        str     r2, [r8, #8]
        str     r3, [r8, #12]

SymCryptAesCbcDecryptNoData

        EPILOG_STACK_FREE 32
        EPILOG_POP {r0-r2, r4-r11, pc}

        NESTED_END      SymCryptAesCbcDecryptAsm


;
; VOID
; SYMCRYPT_CALL
; SymCryptAesCtrMsb64(
;     _In_                                        PCSYMCRYPT_AES_EXPANDED_KEY pExpandedKey,
;     _In_reads_bytes_( SYMCRYPT_AES_BLOCK_SIZE ) PBYTE                       pbChainingValue,
;     _In_reads_bytes_( cbData )                  PCBYTE                      pbSrc,
;     _Out_writes_bytes_( cbData )                PBYTE                       pbDst,
;                                                 SIZE_T                      cbData );

        NESTED_ENTRY    SymCryptAesCtrMsb64Asm

        ;
        ; Input parameters:
        ;   r0 = pExpandedKey
        ;   r1 = pbChainingValue
        ;   r2 = pbSrc
        ;   r3 = pbDst
        ;   [sp] = cbData
        ;

        PROLOG_PUSH {r0-r2, r4-r11, lr}
        PROLOG_STACK_ALLOC 32

        ;
        ; Stack layout:
        ;   [sp] = pbDst
        ;   [sp+4] = pbSrcEnd
        ;   [sp+16] = local copy of chaining data
        ;   [sp+32] = r0 = pbExpandedKey
        ;   [sp+36] = r1 = pbChainingValue
        ;   [sp+40] = r2 = pbSrc
        ;   [sp+80] = cbData
        ;

        SYMCRYPT_CHECK_MAGIC r4, r5, r0, SYMCRYPT_AES_EXPANDED_KEY_magic

        pld     [r2]                    ; prefetch source data
        ldr     r4, [sp, #80]           ; r4 = cbData
        ldr     r9, [r0, #SYMCRYPT_AES_EXPANDED_KEY_lastEncRoundKey] ; r9 = last enc round key (invariant)
        mov     r10, r2                 ; r10 = pbSrc
        mov32   r12, SymCryptAesSboxMatrixMult ; r12 = pointer to lookup table (invariant)
        bics    r4, r4, #15             ; r4 &= ~15
        beq     SymCryptAesCtrMsb64NoData ; skip if no data
        adds    r4, r4, r2              ; r4 = pbSrc + cbData
        strd    r3, r4, [sp]            ; save pbDst/pbSrcEnd at [sp]

        pld     [r10, #32]              ; prefetch source data
        mov     r3, r1                  ; load chaining state from pbChainingValue
        ldr     r0, [r3, #0]            ;
        ldr     r1, [r3, #4]            ;
        ldr     r2, [r3, #8]            ;
        ldr     r3, [r3, #12]           ;

        strd    r0, r1, [sp, #16]       ; save a local copy
        strd    r2, r3, [sp, #24]       ;

SymCryptAesCtrMsb64AsmLoop
        ;
        ; Loop register setup
        ;   r0,r1,r2,r3 = chaining state
        ;   r8 = pbSrc
        ;   r9 = last round key to use
        ;   r10 = pbSrc
        ;   r12 = SboxMatrixMult
        ;

        ldr     r8, [sp, #32]           ; r8 = first round key
        AES_ENCRYPT
        ;
        ; Plaintext in r0, r1, r2, r3
        ; r8 points to first round key to use
        ; r9 is last key to use (unchanged)
        ; r12 points to SboxMatrixMult (unchanged)
        ; Ciphertext ends up in r4, r5, r6, r7
        ;

        ldr     r0, [r10, #0]           ; load plaintext
        ldr     r1, [r10, #4]           ;
        ldr     r2, [r10, #8]           ;
        ldr     r3, [r10, #12]          ;
        pld     [r10, #64]              ; prefetch source data

        ldrd    r8, lr, [sp]            ; fetch pbDst/pbSrcEnd

        eors    r0, r0, r4              ; exclusive-OR against encrypt results
        eors    r1, r1, r5              ;
        eors    r2, r2, r6              ;
        eors    r3, r3, r7              ;

        str     r0, [r8, #0]            ; store to destination
        str     r1, [r8, #4]            ;
        str     r2, [r8, #8]            ;
        str     r3, [r8, #12]           ;

        ldrd    r0, r1, [sp, #16]       ; load chaining state
        ldrd    r2, r3, [sp, #24]       ;

        add     r8, r8, #16             ; pbDst += 16
        add     r10, r10, #16           ; pbSrc += 16
        str     r8, [sp]                ; save pbDst

        rev     r3, r3                  ; reverse the second qword
        rev     r2, r2                  ;
        adds    r3, r3, #1              ; increment the counter
        adcs    r2, r2, #0              ;
        rev     r3, r3                  ; re-reverse the second word
        rev     r2, r2                  ;
        strd    r2, r3, [sp, #24]       ; write updated state

        cmp     r10, lr                 ; done?
        blo     SymCryptAesCtrMsb64AsmLoop ; loop until finished

        ldr     r0, [sp, #36]           ; get pbChainingValue
        movs    r1, #0                  ; get 0 in r1
        str     r2, [r0, #8]            ; write back modified part of chaining state
        str     r3, [r0, #12]           ;
        strd    r1, r1, [sp, #16]       ; wipe the stack copy
        strd    r1, r1, [sp, #24]       ;

SymCryptAesCtrMsb64NoData

        EPILOG_STACK_FREE 32
        EPILOG_POP {r0-r2, r4-r11, pc}  ; return

        NESTED_END      SymCryptAesCtrMsb64Asm

        end

