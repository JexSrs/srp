import {Parameters} from "./Parameters";
import {
    generateRandomBigint,
    hash,
    hashBitCount,
    hashPadded
} from "./utils";
import {
    bigintToBytes,
    bytesToBigint,
    stringToByteArray
} from './transformations'
import {
    modPow, ZERO
} from './bigintMath'

export class Routines {
    constructor(public readonly parameters: Parameters = new Parameters()) {}

    /**
     * Hash a collection of byte arrays.
     * @param ab
     */
    hash(...ab: Uint8Array[]): Uint8Array {
        return hash(this.parameters, ...ab);
    }

    /**
     * Left pad with zeroes and generates a hash from it.
     * @param ab
     */
    hashPadded(...ab: Uint8Array[]): Uint8Array {
        const targetLength = Math.trunc((this.parameters.NBits + 7) / 8);
        return hashPadded(this.parameters, targetLength, ...ab);
    }

    /** Computes K. */
    computeK(): bigint {
        return bytesToBigint(
            this.hashPadded(
                bigintToBytes(this.parameters.primeGroup.N),
                bigintToBytes(this.parameters.primeGroup.g)
            )
        );
    }

    /**
     * Generates a random salt.
     * @param numBytes Length of salt in bytes.
     */
    generateRandomSalt(numBytes?: number): bigint {
        const HBits = hashBitCount(this.parameters);
        const saltBytes = numBytes || (2 * HBits) / 8;
        return generateRandomBigint(saltBytes);
    }

    /**
     * Computes X.
     * @param identity
     * @param salt
     * @param password
     */
    computeX(identity: string, salt: bigint, password: string): bigint {
        return bytesToBigint(
            this.hash(
                bigintToBytes(salt),
                this.computeIdentityHash(identity, password),
            )
        );
    }

    /**
     * Computes X for step 2.
     * @param salt
     * @param identityHash
     */
    computeXStep2(salt: bigint, identityHash: Uint8Array): bigint {
        return bytesToBigint(
            this.hash(
                bigintToBytes(salt),
                identityHash
            )
        );
    }

    /**
     * Generates an identity based on user's identity and password.
     * @param identity
     * @param password
     */
    computeIdentityHash(identity: string, password: string): Uint8Array {
        return this.hash(stringToByteArray(`${identity}:${password}`));
    }

    /**
     * Generates a verifier based on x.
     * @param x
     */
    computeVerifier(x: bigint): bigint {
        return modPow(this.parameters.primeGroup.g, x, this.parameters.primeGroup.N);
    }

    /**
     * Generates private key. It will be used by the server (b) or the client (a).
     */
    generatePrivateValue(): bigint {
        const numBits = Math.max(256, this.parameters.NBits);
        let bi: bigint;

        do {
            bi = generateRandomBigint(numBits / 8) % this.parameters.primeGroup.N;
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
     * @param verifier
     * @param b The server's private value.
     */
    computeServerPublicValue(k: bigint, verifier: bigint, b: bigint): bigint {
        return (
            (modPow(this.parameters.primeGroup.g, b, this.parameters.primeGroup.N) + verifier * k) %
            this.parameters.primeGroup.N
        );
    }

    /**
     * Checks if public value is valid.
     * @param value
     */
    isValidPublicValue(value: bigint): boolean {
        return value % this.parameters.primeGroup.N !== ZERO;
    }

    /**
     * Computes U.
     * @param A The public value of client.
     * @param B The public value of server.
     */
    computeU(A: bigint, B: bigint): bigint {
        return bytesToBigint(
            this.hashPadded(
                bigintToBytes(A),
                bigintToBytes(B)
            )
        );
    }

    /**
     * Computes M1 which is the client's evidence.
     * @param identity The user's identity.
     * @param salt The random salt
     * @param A The client's public value.
     * @param B The server's public value.
     * @param sessionKey The session key.
     */
    computeClientEvidence(identity: string, salt: bigint, A: bigint, B: bigint, sessionKey: bigint): bigint {
        return bytesToBigint(
            this.hash(
                stringToByteArray(identity),
                bigintToBytes(salt),
                bigintToBytes(A),
                bigintToBytes(B),
                bigintToBytes(sessionKey)
            )
        );
    }

    /**
     * Computes M2 which is the server's evidence.
     * @param A The client's public value.
     * @param M1 The client's evidence.
     * @param sessionKey The session key.
     */
    computeServerEvidence(A: bigint, M1: bigint, sessionKey: bigint): bigint {
        return bytesToBigint(
            this.hash(bigintToBytes(A),
                bigintToBytes(M1),
                bigintToBytes(sessionKey)
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
     * @param verifier The verifier.
     * @param u The U.
     * @param A The client's public value.
     * @param b The server's private value.
     */
    computeServerSessionKey(verifier: bigint, u: bigint, A: bigint, b: bigint): bigint {
        const N = this.parameters.primeGroup.N
        return modPow(modPow(verifier, u, N) * A, b, N);
    }
}