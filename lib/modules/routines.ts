import {Parameters} from "./parameters";
import {generateRandomBigint, hash, hashBitCount, hashPadded} from "./utils";
import {bigintToBytes, bytesToBigint, stringToByteArray} from './transformations'

export class Routines {
    constructor(public readonly options: Parameters = new Parameters()) {
    }

    /**
     * Calculates (x**pow) % mod
     * @param x base, non negative big int.
     * @param pow power, non-negative power.
     * @param mod modulo, positive modulo for division.
     */
    private modPow(x: bigint, pow: bigint, mod: bigint): bigint {
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
            }
            else {
                x = (x * x) % mod;
                pow /= TWO;
            }
        }

        return result;
    }

    /**
     * Hash a collection of byte arrays.
     * @param ab
     */
    hash(...ab: Uint8Array[]): Uint8Array {
        return hash(this.options, ...ab);
    }

    /**
     * Left pad with zeroes and generates a hash from it.
     * @param ab
     */
    hashPadded(...ab: Uint8Array[]): Uint8Array {
        const targetLength = Math.trunc((this.options.options.NBits + 7) / 8);
        return hashPadded(this.options, targetLength, ...ab);
    }

    /** Computes K. */
    computeK(): bigint {
        return bytesToBigint(
            this.hashPadded(
                bigintToBytes(this.options.options.primeGroup.N),
                bigintToBytes(this.options.options.primeGroup.g)
            )
        );
    }

    /**
     * Generates a random salt.
     * @param numBytes Length of salt in bytes.
     */
    generateRandomSalt(numBytes?: number): bigint {
        const HBits = hashBitCount(this.options);
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
        return this.modPow(this.options.options.primeGroup.g, x, this.options.options.primeGroup.N);
    }

    /**
     * Generates private key ("a" or "b") for the client or server.
     */
    generatePrivateValue(): bigint {
        const numBits = Math.max(256, this.options.options.NBits);
        let bi: bigint;

        do {
            bi = generateRandomBigint(numBits / 8) % this.options.options.primeGroup.N;
        }
        while (bi === BigInt(0));

        return bi;
    }

    /**
     * Generates client's public key "A".
     * @param a The client's private key "a".
     */
    computeClientPublicValue(a: bigint): bigint {
        return this.modPow(this.options.options.primeGroup.g, a, this.options.options.primeGroup.N);
    }

    /**
     * Generates the server's public key "B".
     * @param k The k.
     * @param verifier
     * @param b The server's private key "b".
     */
    computeServerPublicValue(k: bigint, verifier: bigint, b: bigint): bigint {
        return (
            (this.modPow(this.options.options.primeGroup.g, b, this.options.options.primeGroup.N) + verifier * k) %
            this.options.options.primeGroup.N
        );
    }

    /**
     * Checks if public key is valid.
     * @param value
     */
    isValidPublicValue(value: bigint): boolean {
        return value % this.options.options.primeGroup.N !== BigInt(0);
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
        const N = this.options.options.primeGroup.N;
        const exp = u * x + a;
        const tmp = (this.modPow(this.options.options.primeGroup.g, x, N) * k) % N;

        return this.modPow(B + N - tmp, exp, N);
    }

    /**
     * Computes the session key "S" for the server.
     * @param verifier The verifier.
     * @param u The U.
     * @param A The client's public key "A".
     * @param b The server's private key "b".
     */
    computeServerSessionKey(verifier: bigint, u: bigint, A: bigint, b: bigint): bigint {
        const N = this.options.options.primeGroup.N
        return this.modPow(this.modPow(verifier, u, N) * A, b, N);
    }
}