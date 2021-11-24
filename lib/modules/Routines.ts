import {Parameters} from "./Parameters";
import {
    generateRandomBigInt,
    hash,
    hashBitCount,
    hashPadded
} from "./utils";
import {
    bigintToArrayBuffer,
    arrayBufferToBigint,
    stringToArrayBuffer
} from './transformations'
import {
    modPow, ZERO
} from './bigintMath'

export class Routines {
    constructor(public readonly parameters: Parameters = new Parameters()) {}

    /**
     * Generate a hash for multiple ArrayBuffers.
     * @param ab The ArrayBuffers.
     */
    hash(...ab: ArrayBuffer[]): ArrayBuffer {
        return hash(this.parameters, ...ab);
    }

    /**
     * Left pad in ArrayBuffer with zeroes and generates a hash from it.
     * @param ab The ArrayBuffers.
     */
    hashPadded(...ab: ArrayBuffer[]): ArrayBuffer {
        const targetLength = Math.trunc((this.parameters.NBits + 7) / 8);
        return hashPadded(this.parameters, targetLength, ...ab);
    }

    /**
     * Computes K.
     */
    computeK(): bigint {
        return arrayBufferToBigint(
            this.hashPadded(
                bigintToArrayBuffer(this.parameters.primeGroup.N),
                bigintToArrayBuffer(this.parameters.primeGroup.g)
            )
        );
    }

    /**
     * Generates a random salt.
     * @param numBytes Length of salt in bytes.
     */
    generateRandomSalt(numBytes?: number): bigint {
        const HBits = hashBitCount(this.parameters);
        // Recommended salt bytes is > than Hash output bytes. We default to twice
        // the bytes used by the hash
        const saltBytes = numBytes || (2 * HBits) / 8;
        return generateRandomBigInt(saltBytes);
    }

    /**
     * Computes X.
     * @param I The user's identity.
     * @param s The random salt.
     * @param P The user's password.
     */
    computeX(I: string, s: bigint, P: string): bigint {
        return arrayBufferToBigint(
            this.hash(
                bigintToArrayBuffer(s),
                this.computeIdentityHash(I, P),
            )
        );
    }

    /**
     * Computes X for step 2.
     * @param s The user's salt
     * @param identityHash The generated identity hash.
     */
    computeXStep2(s: bigint, identityHash: ArrayBuffer): bigint {
        return arrayBufferToBigint(
            this.hash(
                bigintToArrayBuffer(s),
                identityHash
            )
        );
    }

    /**
     * Generates an identity based on user's Identity and Password.
     * @param I The user's identity.
     * @param P The user's password.
     */
    computeIdentityHash(I: string, P: string): ArrayBuffer {
        return this.hash(stringToArrayBuffer(`${I}:${P}`));
    }

    /**
     * Generates a verifier based on x.
     * @param x The x.
     */
    computeVerifier(x: bigint): bigint {
        return modPow(this.parameters.primeGroup.g, x, this.parameters.primeGroup.N);
    }

    /**
     * Generates private value for server (b) or client (a).
     */
    generatePrivateValue(): bigint {
        const numBits = Math.max(256, this.parameters.NBits);
        let bi: bigint;

        do {
            bi = generateRandomBigInt(numBits / 8) % this.parameters.primeGroup.N;
        }
        while (bi === ZERO);

        return bi;
    }

    /**
     * Generates the public value for the client.
     * @param a The client's private value.
     */
    computeClientPublicValue(a: bigint): bigint {
        return modPow(this.parameters.primeGroup.g, a, this.parameters.primeGroup.N);
    }

    /**
     * Generates the public value for the client.
     * @param k The k.
     * @param v The verifier.
     * @param b The server's private value.
     */
    computeServerPublicValue(k: bigint, v: bigint, b: bigint): bigint {
        return (
            (modPow(this.parameters.primeGroup.g, b, this.parameters.primeGroup.N) + v * k) %
            this.parameters.primeGroup.N
        );
    }

    /**
     * Checks if public value is valid.
     * @param value The value.
     */
    isValidPublicValue(value: bigint): boolean {
        return value % this.parameters.primeGroup.N !== ZERO;
    }

    /**
     * Computes U.
     * @param A The public value of client.
     * @param B The public value of server/\.
     */
    computeU(A: bigint, B: bigint): bigint {
        return arrayBufferToBigint(
            this.hashPadded(
                bigintToArrayBuffer(A),
                bigintToArrayBuffer(B)
            )
        );
    }

    /**
     * Computes M1 which is the client's evidence.
     * @param I The user's identity.
     * @param s The random salt
     * @param A The client's public value.
     * @param B The server's public value.
     * @param S The session key.
     */
    computeClientEvidence(I: string, s: bigint, A: bigint, B: bigint, S: bigint): bigint {
        return arrayBufferToBigint(
            this.hash(
                stringToArrayBuffer(I),
                bigintToArrayBuffer(s),
                bigintToArrayBuffer(A),
                bigintToArrayBuffer(B),
                bigintToArrayBuffer(S)
            )
        );
    }

    /**
     * Computes M2 which is the server's evidence.
     * @param A The client's public value.
     * @param M1 The client's evidence.
     * @param S The session key.
     */
    computeServerEvidence(A: bigint, M1: bigint, S: bigint): bigint {
        return arrayBufferToBigint(
            this.hash(bigintToArrayBuffer(A),
                bigintToArrayBuffer(M1),
                bigintToArrayBuffer(S)
            )
        );
    }

    /**
     * Computes the session key S for the client.
     * @param k The k.
     * @param x The x.
     * @param u The u.
     * @param a The client's private value.
     * @param B The server's public value.
     */
    computeClientSessionKey(k: bigint, x: bigint, u: bigint, a: bigint, B: bigint): bigint {
        const N = this.parameters.primeGroup.N;
        const exp = u * x + a;
        const tmp = (modPow(this.parameters.primeGroup.g, x, N) * k) % N;

        return modPow(B + N - tmp, exp, N);
    }

    /**
     * Computes the session key S for the server.
     * @param N The prime N
     * @param v The verifier.
     * @param u The U.
     * @param A The client's public value.
     * @param b The server's private value.
     */
    computeServerSessionKey(v: bigint, u: bigint, A: bigint, b: bigint): bigint {
        const N = this.parameters.primeGroup.N
        return modPow(modPow(v, u, N) * A, b, N);
    }
}