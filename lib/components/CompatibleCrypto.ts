import {HashFunction} from "./HashFunction";

export interface CompatibleCrypto {
    hashFunctions: { [algo: string]: HashFunction };
    randomBytes: (length: number) => Uint8Array;
}