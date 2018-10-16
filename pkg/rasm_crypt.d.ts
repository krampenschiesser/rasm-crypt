/* tslint:disable */
export function scrypt_simple(pw: Uint8Array, salt: Uint8Array, output_length: number): Uint8Array;

export function scrypt(arg0: Uint8Array, arg1: Uint8Array, arg2: number, arg3: number, arg4: number, arg5: number): Uint8Array;

export function encrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, input: Uint8Array): EncryptionResult;

export function decrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, input: Uint8Array, tag: Uint8Array): Uint8Array;

export function to_uint8(text: string): Uint8Array;

export function to_utf8(binary: Uint8Array): string;

export function isAvailable(): boolean;

export class EncryptionResult {
free(): void;

 get_auth_tag(): Uint8Array;

 get_ciphertext(): Uint8Array;

}
