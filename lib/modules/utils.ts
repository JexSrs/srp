import {Routines} from "./routines";
import {IVerifierAndSalt} from "../components/types";
import {bigintToBytes, bytesToBigint,} from './transformations'
import {HashFunction} from "../components/cryptoTypes";

/**
 * Left pad bytes array with zeroes.
 * @param array
 * @param targetLength Length of the target array in bytes.
 * @returns Padded array or original array if targetLength is less than original
 *          array length.
 */
export function padStartBytesArray(array: Uint8Array, targetLength: number): Uint8Array {
    if (array.length >= targetLength)
        return array;

    const u8 = new Uint8Array(targetLength);
    u8.fill(0, 0, targetLength - array.length);
    u8.set(array, targetLength - array.length);
    return u8;
}

/**
 * Generates a hash from byte arrays.
 * @param hf
 * @param bytes
 */
export function hash(hf: HashFunction, ...bytes: Uint8Array[]): Uint8Array {
    const length = bytes.reduce((p, c) => p + c.byteLength, 0);

    const target = new Uint8Array(length);
    for (let offset = 0, i = 0; i < bytes.length; i++) {
        target.set(new Uint8Array(bytes[i]), offset);
        offset += bytes[i].byteLength;
    }

    return hf(target);
}

/**
 * Left pad byte arrays with zeroes and generates a hash from it.
 * @param hf
 * @param targetLen Length of the target array in bytes.
 * @param arrays
 */
export function hashPadded(hf: HashFunction, targetLen: number, ...arrays: Uint8Array[]): Uint8Array {
    const arraysPadded = arrays.map((bytesArray) =>
        padStartBytesArray(bytesArray, targetLen),
    );

    return hash(hf, ...arraysPadded);
}

/**
 * Generates a secure random string of ASCII characters.
 * @param length
 */
export function generateRandomString(length: number): string {
    const u8 = Routines.randomBytes(length / 2); // each byte has 2 hex digits
    return u8.reduce((str, i) => {
        const hex = i.toString(16).toString();
        if (hex.length === 1)
            return str + "0" + hex;

        return str + hex;
    }, "").slice(0, length);
}

/**
 * Generates random big integer.
 * @param numBytes Length of the bigint in bytes.
 */
export function generateRandomBigint(numBytes: number = 16): bigint {
    return bytesToBigint(Routines.randomBytes(numBytes));
}

export function hashBitCount(hf: HashFunction): number {
    return hash(hf, bigintToBytes(BigInt(1))).byteLength * 8;
}

/**
 * Calculates (x**pow) % mod
 * @param x base, non negative big int.
 * @param pow power, non-negative power.
 * @param mod modulo, positive modulo for division.
 */
export function modPow(x: bigint, pow: bigint, mod: bigint): bigint {
    const ZERO: bigint = BigInt(0);
    const ONE: bigint = BigInt(1);
    const TWO: bigint = BigInt(2);

    if (x < ZERO) throw new Error("Invalid base: " + x.toString());
    if (pow < ZERO) throw new Error("Invalid power: " + pow.toString());
    if (mod < ONE) throw new Error("Invalid modulo: " + mod.toString());

    let result: bigint = ONE;
    while (pow > ZERO) {
        if (pow % TWO == ONE) {
            result = (x * result) % mod;
            pow -= ONE;
        } else {
            x = (x * x) % mod;
            pow /= TWO;
        }
    }

    return result;
}

/**
 * Generates a random verifier.
 * @param routines
 * @param identity
 * @param salt
 * @param password
 */
export function createVerifier(routines: Routines, identity: string, salt: bigint, password: string): bigint {
    if (!identity || !identity.trim()) throw new Error("Identity (I) must not be null or empty.")
    if (!salt) throw new Error("Salt (s) must not be null.");
    if (!password || !password.trim()) throw new Error("Password (P) must not be null  or empty.");

    const x = routines.computeX(identity, salt, password);
    return routines.computeVerifier(x);
}

/**
 * Generates salt and verifier.
 * @param routines
 * @param identity
 * @param password
 * @param sBytes Length of salt in bytes.
 */
export function generateVerifierAndSalt(routines: Routines, identity: string, password: string, sBytes?: number): IVerifierAndSalt {
    const s = routines.generateRandomSalt(sBytes);

    return {salt: s.toString(16), verifier: createVerifier(routines, identity, s, password).toString(16)};
}

