import {Options} from "./options";

export type PrimeGroup = {
    N: bigint; // the prime
    g: bigint;
};

export type HashFunction = (data: Uint8Array) => Uint8Array;