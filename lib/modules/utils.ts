import {Parameters} from "./Parameters";
import {Crypto} from "./crypto";
import {Routines} from "./Routines";
import {IVerifierAndSalt} from "../components/IVerifierAndSalt";
import {
    bigintToArrayBuffer,
    arrayBufferToBigint,
} from './transformations'
import {ONE} from "./bigintMath";

const cc = Crypto.compatibleCrypto()

/**
 * Left pad ArrayBuffer with zeroes.
 * @param ab - ArrayBuffer to pad
 * @param targetLength Length of the target array in bytes.
 * @returns Padded array or original array if targetLength is less than original
 *          array length.
 */
export function padStartArrayBuffer(ab: ArrayBuffer, targetLength: number): ArrayBuffer {
    const u8 = new Uint8Array(ab);
    if (u8.length < targetLength) {
        const tmp = new Uint8Array(targetLength);
        tmp.fill(0, 0, targetLength - u8.length);
        tmp.set(u8, targetLength - u8.length);
        return tmp;
    }
    return u8;
}

/**
 * Generates a hash using an ArrayBuffer.
 * @param parameters The parameters used for hashing.
 * @param arrays The arrays that will be hashed.
 */
export function hash(parameters: Parameters, ...arrays: ArrayBuffer[]): ArrayBuffer {
    const length = arrays.reduce((p, c) => p + c.byteLength, 0);

    const target = new Uint8Array(length);
    for (let offset = 0, i = 0; i < arrays.length; i++) {
        target.set(new Uint8Array(arrays[i]), offset);
        offset += arrays[i].byteLength;
    }

    return parameters.hash(target);
}

/**
 * Left pad in ArrayBuffer with zeroes and generates a hash from it.
 * @param parameters The parameters used fro hashing.
 * @param targetLen Length of the target array in bytes.
 * @param arrays The arrays that the transformation will be applied.
 */
export function hashPadded(parameters: Parameters, targetLen: number, ...arrays: ArrayBuffer[]): ArrayBuffer {
    const arraysPadded = arrays.map((arrayBuffer) =>
        padStartArrayBuffer(arrayBuffer, targetLen),
    );

    return hash(parameters, ...arraysPadded);
}

/**
 * Generates random ArrayBuffer.
 * @param numBytes Length of the ArrayBuffer in bytes.
 */
function generateRandom(numBytes: number): ArrayBuffer {
    const u8 = new Uint8Array(numBytes);
    cc.randomBytes(u8);
    return u8.buffer;
}

/**
 * Generates random string of ASCII characters using crypto secure random generator.
 * @param characterCount The length of the result string.
 * @return string The random string.
 */
export function generateRandomString(characterCount: number): string {
    const u8 = new Uint8Array(Math.ceil(characterCount / 2)); // each byte has 2 hex digits
    cc.randomBytes(u8);
    return u8.reduce((str, i) => {
        const hex = i.toString(16).toString();
        if (hex.length === 1)
            return str + "0" + hex;

        return str + hex;
    }, "").slice(0, characterCount);
}

/**
 * Generates random big integer.
 * @param numBytes Length of the bigInt in bytes.
 */
export function generateRandomBigint(numBytes: number = 16): bigint {
    return arrayBufferToBigint(generateRandom(numBytes));
}

/**
 * Generates a random verifier using the user's Identity, salt and Password.
 * @param routines The routines used for hashing.
 * @param I The user's identity.
 * @param s The random salt.
 * @param P The user's Password
 */
export function createVerifier(routines: Routines, I: string, s: bigint, P: string): bigint {
    if (!I || !I.trim()) throw new Error("Identity (I) must not be null or empty.")
    if (!s) throw new Error("Salt (s) must not be null.");
    if (!P || !P.trim()) throw new Error("Password (P) must not be null  or empty.");

    const x = routines.computeX(I, s, P);
    return routines.computeVerifier(x);
}

/**
 * Generates salt and verifier.
 * @param routines The routines used for hashing.
 * @param I The user's identity.
 * @param P The user's password.
 * @param sBytes Length of salt in bytes.
 */
export function generateVerifierAndSalt(routines: Routines, I: string, P: string, sBytes?: number): IVerifierAndSalt {
    const s = routines.generateRandomSalt(sBytes);

    return {salt: s.toString(16), verifier: createVerifier(routines, I, s, P).toString(16)};
}

export function hashBitCount(parameters: Parameters): number {
    return hash(parameters, bigintToArrayBuffer(ONE)).byteLength * 8;
}




