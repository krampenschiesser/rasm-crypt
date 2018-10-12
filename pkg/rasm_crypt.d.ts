/* tslint:disable */
export function scrypt_simple(arg0: Uint8Array, arg1: Uint8Array, arg2: number): Uint8Array;

export function scrypt(arg0: Uint8Array, arg1: Uint8Array, arg2: number, arg3: number, arg4: number, arg5: number): Uint8Array;

export function encrypt(arg0: Uint8Array, arg1: Uint8Array, arg2: Uint8Array, arg3: Uint8Array): EncryptionResult;

export function decrypt(arg0: Uint8Array, arg1: Uint8Array, arg2: Uint8Array, arg3: Uint8Array, arg4: Uint8Array): Uint8Array;

export function to_uint8(arg0: string): Uint8Array;

export function to_utf8(arg0: Uint8Array): string;

export class EncryptionResult {
free(): void;

 get_auth_tag(): Uint8Array;

 get_ciphertext(): Uint8Array;

}
