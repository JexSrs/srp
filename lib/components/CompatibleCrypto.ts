import {HashFunction} from "./HashFunction";

export interface CompatibleCrypto {
    hashFunctions: { [key: string]: HashFunction };
    randomBytes: (array: Uint8Array) => Uint8Array;
}