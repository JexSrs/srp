import {Parameters} from "./Parameters";
import {Crypto} from "./crypto";
import {Routines} from "./Routines";
import {IVerifierAndSalt} from "../components/IVerifierAndSalt";

export const ZERO: bigint = BigInt(0);
export const ONE: bigint = BigInt(1);
export const TWO: bigint = BigInt(2);

const cc = Crypto.compatibleCrypto()

export function bigintToArrayBuffer(n: bigint): ArrayBuffer {
    const hex = n.toString(16);
    const arrayBuffer = new ArrayBuffer(Math.ceil(hex.length / 2));
    const u8 = new Uint8Array(arrayBuffer);
    let offset = 0;
    // handle toString(16) not padding
    if (hex.length % 2 !== 0) {
        u8[0] = parseInt(hex[0], 16);
        offset = 1;
    }
    for (let i = 0; i < arrayBuffer.byteLength; i++) {
        u8[i + offset] = parseInt(
            hex.slice(2 * i + offset, 2 * i + 2 + offset),
            16,
        );
    }
    return arrayBuffer;
}

export function arrayBufferToBigint(ab: ArrayBuffer): bigint {
    const hex: string[] = [];
    // we can't use map here because map will return Uint8Array which will screw up the parsing below
    new Uint8Array(ab).forEach((i) => {
        hex.push(("0" + i.toString(16)).slice(-2)); // i.toString(16) will transform 01 to 1, so we add it back on and slice takes the last two chars
    });
    return BigInt(`0x${hex.join("")}`);
}

/**
 * Convert string into ArrayBuffer.
 * @param s Any UTF8 string.
 */
export function stringToArrayBuffer(s: string): ArrayBuffer {
    return new TextEncoder().encode(s).buffer;
}

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

export function hash(parameters: Parameters, ...arrays: ArrayBuffer[]): ArrayBuffer {
    const length = arrays.reduce((p, c) => p + c.byteLength, 0);
    const target = new Uint8Array(length);
    for (let offset = 0, i = 0; i < arrays.length; i++) {
        target.set(new Uint8Array(arrays[i]), offset);
        offset += arrays[i].byteLength;
    }
    return parameters.hash(target);
}

export function hashPadded(parameters: Parameters, targetLen: number, ...arrays: ArrayBuffer[]): ArrayBuffer {
    const arraysPadded = arrays.map((arrayBuffer) =>
        padStartArrayBuffer(arrayBuffer, targetLen),
    );
    return hash(parameters, ...arraysPadded);
}

function generateRandom(numBytes: number): ArrayBuffer {
    const u8 = new Uint8Array(numBytes);
    cc.randomBytes(u8);
    return u8.buffer;
}

/**
 * Generates random string of ASCII characters using crypto secure random generator.
 * @param characterCount The length of the result string.
 * @return The string.
 */
export function generateRandomString(characterCount: number = 10) {
    const u8 = new Uint8Array(Math.ceil(Math.ceil(characterCount / 2))); // each byte has 2 hex digits
    cc.randomBytes(u8);
    return u8.reduce((str, i) => {
        const hex = i.toString(16).toString();
        if (hex.length === 1) {
            return str + "0" + hex;
        }
        return str + hex;
    }, "").slice(0, characterCount); // so we don't go over when characterCount is odd
}

export function generateRandomBigInt(numBytes: number = 16): bigint {
    return arrayBufferToBigint(generateRandom(numBytes));
}

export function createVerifier(routines: Routines, I: string, s: bigint, P: string,): bigint {
    if (!I || !I.trim()) throw new Error("Identity (I) must not be null or empty.")
    if (!s) throw new Error("Salt (s) must not be null.");
    if (!P) throw new Error("Password (P) must not be null");

    const x = routines.computeX(I, s, P);

    return routines.computeVerifier(x);
}

export function createVerifierAndSalt(routines: Routines, I: string, P: string, sBytes?: number,): IVerifierAndSalt {
    const s = routines.generateRandomSalt(sBytes);

    return {salt: s, verifier: createVerifier(routines, I, s, P),};
}

export function hashBitCount(parameters: Parameters): number {
    return hash(parameters, bigintToArrayBuffer(ONE)).byteLength * 8;
}

/**
 * Calculates (x**pow) % mod
 * @param x base, non negative big int.
 * @param pow power, non negative power.
 * @param mod modulo, positive modulo for division.
 */
export function modPow(x: bigint, pow: bigint, mod: bigint): bigint {
    if (x < ZERO) throw new Error("Invalid base: " + x.toString());
    if (pow < ZERO) throw new Error("Invalid power: " + pow.toString());
    if (mod < ONE) throw new Error("Invalid modulo: " + mod.toString());

    let result: bigint = ONE;
    while (pow > ZERO) {
        if (pow % TWO == ONE) {
            result = (x * result) % mod;
            pow -= ONE;
        }
        else {
            x = (x * x) % mod;
            pow /= TWO;
        }
    }

    return result;
}




