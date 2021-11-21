import {Parameters} from "./Parameters";
import {
    arrayBufferToBigint,
    bigintToArrayBuffer,
    generateRandomBigInt,
    hash,
    hashBitCount,
    hashPadded, modPow,
    stringToArrayBuffer, ZERO
} from "./utils";

export class Routines {
    constructor(public readonly parameters: Parameters = new Parameters()) {}

    hash(...ab: ArrayBuffer[]): ArrayBuffer {
        return hash(this.parameters, ...ab);
    }

    hashPadded(...ab: ArrayBuffer[]): ArrayBuffer {
        const targetLength = Math.trunc((this.parameters.NBits + 7) / 8);
        return hashPadded(this.parameters, targetLength, ...ab);
    }

    computeK(): bigint {
        return arrayBufferToBigint(this.hashPadded(bigintToArrayBuffer(this.parameters.primeGroup.N), bigintToArrayBuffer(this.parameters.primeGroup.g)));
    }

    generateRandomSalt(numBytes?: number): bigint {
        const HBits = hashBitCount(this.parameters);
        // Recommended salt bytes is > than Hash output bytes. We default to twice
        // the bytes used by the hash
        const saltBytes = numBytes || (2 * HBits) / 8;
        return generateRandomBigInt(saltBytes);
    }

    computeX(I: string, s: bigint, P: string): bigint {
        return arrayBufferToBigint(
            this.hash(
                bigintToArrayBuffer(s),
                this.computeIdentityHash(I, P),
            )
        );
    }

    computeXStep2(s: bigint, identityHash: ArrayBuffer): bigint {
        return arrayBufferToBigint(this.hash(bigintToArrayBuffer(s), identityHash));
    }

    computeIdentityHash(_: string, P: string): ArrayBuffer {
        return this.hash(stringToArrayBuffer(P));
    }

    computeVerifier(x: bigint): bigint {
        return modPow(this.parameters.primeGroup.g, x, this.parameters.primeGroup.N);
    }

    generatePrivateValue(): bigint {
        const numBits = Math.max(256, this.parameters.NBits);
        let bi: bigint;

        do {
            bi = generateRandomBigInt(numBits / 8) % this.parameters.primeGroup.N;
        } while (bi === ZERO);

        return bi;
    }

    computeClientPublicValue(a: bigint): bigint {
        return modPow(this.parameters.primeGroup.g, a, this.parameters.primeGroup.N);
    }

    isValidPublicValue(value: bigint): boolean {
        return value % this.parameters.primeGroup.N !== ZERO;
    }

    computeU(A: bigint, B: bigint): bigint {
        return arrayBufferToBigint(this.hashPadded(bigintToArrayBuffer(A), bigintToArrayBuffer(B)));
    }

    computeClientEvidence(_I: string, _s: bigint, A: bigint, B: bigint, S: bigint): bigint {
        return arrayBufferToBigint(this.hash(bigintToArrayBuffer(A), bigintToArrayBuffer(B), bigintToArrayBuffer(S)));
    }

    computeServerEvidence(A: bigint, M1: bigint, S: bigint): bigint {
        return arrayBufferToBigint(this.hash(bigintToArrayBuffer(A), bigintToArrayBuffer(M1), bigintToArrayBuffer(S),));
    }

    computeClientSessionKey(k: bigint, x: bigint, u: bigint, a: bigint, B: bigint): bigint {
        const N = this.parameters.primeGroup.N;
        const exp = u * x + a;
        const tmp = (modPow(this.parameters.primeGroup.g, x, N) * k) % N;

        return modPow(B + N - tmp, exp, N);
    }
}