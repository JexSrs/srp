import {Options} from "./options";


export type PrimeGroup = {
    N: bigint; // the prime
    g: bigint; // a generator of the multiplicative group Zn
};

export type HashFunction = (data: Uint8Array) => Uint8Array;

/**
 * @param identity The user's identity (a username, email etc).
 * @param password The user's passphrase (this is secret and will never be saved in the library).
 * @param sBytes The salt's length.
 */
export type VerifierOptions = Partial<Options> & {
    identity: string;
    password: string;
    sBytes?: number;
};