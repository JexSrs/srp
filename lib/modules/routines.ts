import {Parameters} from "./parameters";
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
     * Computes X that will be used in step 2 from client.
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
     * Generates a hash based on user's identity and password.
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
     * Generates private key ("a" or "b") for the client or server.
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
     * Generates client's public key "A".
     * @param a The client's private key "a".
     */
    computeClientPublicValue(a: bigint): bigint {
        return modPow(this.parameters.primeGroup.g, a, this.parameters.primeGroup.N);
    }

    /**
     * Generates the server's public key "B".
     * @param k The k.
     * @param verifier
     * @param b The server's private key "b".
     */
    computeServerPublicValue(k: bigint, verifier: bigint, b: bigint): bigint {
        return (
            (modPow(this.parameters.primeGroup.g, b, this.parameters.primeGroup.N) + verifier * k) %
            this.parameters.primeGroup.N
        );
    }

    /**
     * Checks if public key is valid.
     * @param value
     */
    isValidPublicValue(value: bigint): boolean {
        return value % this.parameters.primeGroup.N !== ZERO;
    }

    /**
     * Computes U.
     * @param A The client's public key "A".
     * @param B The server's public key "B".
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
     * Computes client's evidence message "M1".
     * @param identity The user's identity.
     * @param salt The random salt
     * @param A The client's public key "A".
     * @param B The server's public key "B".
     * @param sessionKey The session key "S".
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
     * Computes server's evidence message "M2".
     * @param A The client's public value "A".
     * @param M1 The client's evidence message "M2".
     * @param sessionKey The session key "S".
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
     * Computes the session key "S" for the client.
     * @param k The k.
     * @param x The x.
     * @param u The u.
     * @param a The client's private key "a".
     * @param B The server's public key "B".
     */
    computeClientSessionKey(k: bigint, x: bigint, u: bigint, a: bigint, B: bigint): bigint {
        const N = this.parameters.primeGroup.N;
        const exp = u * x + a;
        const tmp = (modPow(this.parameters.primeGroup.g, x, N) * k) % N;

        return modPow(B + N - tmp, exp, N);
    }

    /**
     * Computes the session key "S" for the server.
     * @param verifier The verifier.
     * @param u The U.
     * @param A The client's public key "A".
     * @param b The server's private key "b".
     */
    computeServerSessionKey(verifier: bigint, u: bigint, A: bigint, b: bigint): bigint {
        const N = this.parameters.primeGroup.N
        return modPow(modPow(verifier, u, N) * A, b, N);
    }
}