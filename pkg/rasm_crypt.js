/* tslint:disable */
import * as wasm from './rasm_crypt_bg';

let cachegetUint8Memory = null;
function getUint8Memory() {
    if (cachegetUint8Memory === null || cachegetUint8Memory.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory;
}

function passArray8ToWasm(arg) {
    const ptr = wasm.__wbindgen_malloc(arg.length * 1);
    getUint8Memory().set(arg, ptr / 1);
    return [ptr, arg.length];
}

function getArrayU8FromWasm(ptr, len) {
    return getUint8Memory().subarray(ptr / 1, ptr / 1 + len);
}

let cachedGlobalArgumentPtr = null;
function globalArgumentPtr() {
    if (cachedGlobalArgumentPtr === null) {
        cachedGlobalArgumentPtr = wasm.__wbindgen_global_argument_ptr();
    }
    return cachedGlobalArgumentPtr;
}

let cachegetUint32Memory = null;
function getUint32Memory() {
    if (cachegetUint32Memory === null || cachegetUint32Memory.buffer !== wasm.memory.buffer) {
        cachegetUint32Memory = new Uint32Array(wasm.memory.buffer);
    }
    return cachegetUint32Memory;
}
/**
* @param {Uint8Array} arg0
* @param {Uint8Array} arg1
* @param {number} arg2
* @returns {Uint8Array}
*/
export function scrypt_simple(arg0, arg1, arg2) {
    const [ptr0, len0] = passArray8ToWasm(arg0);
    const [ptr1, len1] = passArray8ToWasm(arg1);
    const retptr = globalArgumentPtr();
    try {
        wasm.scrypt_simple(retptr, ptr0, len0, ptr1, len1, arg2);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getArrayU8FromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;


    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);
        wasm.__wbindgen_free(ptr1, len1 * 1);

    }

}

/**
* @param {Uint8Array} arg0
* @param {Uint8Array} arg1
* @param {number} arg2
* @param {number} arg3
* @param {number} arg4
* @param {number} arg5
* @returns {Uint8Array}
*/
export function scrypt(arg0, arg1, arg2, arg3, arg4, arg5) {
    const [ptr0, len0] = passArray8ToWasm(arg0);
    const [ptr1, len1] = passArray8ToWasm(arg1);
    const retptr = globalArgumentPtr();
    try {
        wasm.scrypt(retptr, ptr0, len0, ptr1, len1, arg2, arg3, arg4, arg5);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getArrayU8FromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;


    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);
        wasm.__wbindgen_free(ptr1, len1 * 1);

    }

}

/**
* @param {Uint8Array} arg0
* @param {Uint8Array} arg1
* @param {Uint8Array} arg2
* @param {Uint8Array} arg3
* @returns {EncryptionResult}
*/
export function encrypt(arg0, arg1, arg2, arg3) {
    const [ptr0, len0] = passArray8ToWasm(arg0);
    const [ptr1, len1] = passArray8ToWasm(arg1);
    const [ptr2, len2] = passArray8ToWasm(arg2);
    const [ptr3, len3] = passArray8ToWasm(arg3);
    try {
        return EncryptionResult.__wrap(wasm.encrypt(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3));

    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);
        wasm.__wbindgen_free(ptr1, len1 * 1);
        wasm.__wbindgen_free(ptr2, len2 * 1);
        wasm.__wbindgen_free(ptr3, len3 * 1);

    }

}

/**
* @param {Uint8Array} arg0
* @param {Uint8Array} arg1
* @param {Uint8Array} arg2
* @param {Uint8Array} arg3
* @param {Uint8Array} arg4
* @returns {Uint8Array}
*/
export function decrypt(arg0, arg1, arg2, arg3, arg4) {
    const [ptr0, len0] = passArray8ToWasm(arg0);
    const [ptr1, len1] = passArray8ToWasm(arg1);
    const [ptr2, len2] = passArray8ToWasm(arg2);
    const [ptr3, len3] = passArray8ToWasm(arg3);
    const [ptr4, len4] = passArray8ToWasm(arg4);
    const retptr = globalArgumentPtr();
    try {
        wasm.decrypt(retptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getArrayU8FromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;


    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);
        wasm.__wbindgen_free(ptr1, len1 * 1);
        wasm.__wbindgen_free(ptr2, len2 * 1);
        wasm.__wbindgen_free(ptr3, len3 * 1);
        wasm.__wbindgen_free(ptr4, len4 * 1);

    }

}

let cachedTextEncoder = new TextEncoder('utf-8');

function passStringToWasm(arg) {

    const buf = cachedTextEncoder.encode(arg);
    const ptr = wasm.__wbindgen_malloc(buf.length);
    getUint8Memory().set(buf, ptr);
    return [ptr, buf.length];
}
/**
* @param {string} arg0
* @returns {Uint8Array}
*/
export function to_uint8(arg0) {
    const [ptr0, len0] = passStringToWasm(arg0);
    const retptr = globalArgumentPtr();
    try {
        wasm.to_uint8(retptr, ptr0, len0);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getArrayU8FromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;


    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);

    }

}

let cachedTextDecoder = new TextDecoder('utf-8');

function getStringFromWasm(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory().subarray(ptr, ptr + len));
}
/**
* @param {Uint8Array} arg0
* @returns {string}
*/
export function to_utf8(arg0) {
    const [ptr0, len0] = passArray8ToWasm(arg0);
    const retptr = globalArgumentPtr();
    try {
        wasm.to_utf8(retptr, ptr0, len0);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;


    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);

    }

}

function freeEncryptionResult(ptr) {

    wasm.__wbg_encryptionresult_free(ptr);
}
/**
*/
export class EncryptionResult {

    static __wrap(ptr) {
        const obj = Object.create(EncryptionResult.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeEncryptionResult(ptr);
    }

    /**
    * @returns {Uint8Array}
    */
    get_auth_tag() {
        const retptr = globalArgumentPtr();
        wasm.encryptionresult_get_auth_tag(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getArrayU8FromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * @returns {Uint8Array}
    */
    get_ciphertext() {
        const retptr = globalArgumentPtr();
        wasm.encryptionresult_get_ciphertext(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getArrayU8FromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
}

const slab = [{ obj: undefined }, { obj: null }, { obj: true }, { obj: false }];

let slab_next = slab.length;

function addHeapObject(obj) {
    if (slab_next === slab.length) slab.push(slab.length + 1);
    const idx = slab_next;
    const next = slab[idx];

    slab_next = next;

    slab[idx] = { obj, cnt: 1 };
    return idx << 1;
}

export function __wbindgen_string_new(p, l) {
    return addHeapObject(getStringFromWasm(p, l));
}

const stack = [];

function getObject(idx) {
    if ((idx & 1) === 1) {
        return stack[idx >> 1];
    } else {
        const val = slab[idx >> 1];

        return val.obj;

    }
}

function dropRef(idx) {

    idx = idx >> 1;
    if (idx < 4) return;
    let obj = slab[idx];

    obj.cnt -= 1;
    if (obj.cnt > 0) return;

    // If we hit 0 then free up our space in the slab
    slab[idx] = slab_next;
    slab_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropRef(idx);
    return ret;
}

export function __wbindgen_rethrow(idx) { throw takeObject(idx); }

export function __wbindgen_throw(ptr, len) {
    throw new Error(getStringFromWasm(ptr, len));
}

