import * as CryptoJS from "crypto-js";
import {CompatibleCrypto} from "../components/cryptoTypes";
import {wordArrayToBytes} from "./transformations";

export class Crypto {

    private static mCrypto?: CompatibleCrypto = undefined;

    static compatibleCrypto(): CompatibleCrypto {
        if(!this.mCrypto)
            this.mCrypto = {
                randomBytes: (length: number) => wordArrayToBytes(CryptoJS.lib.WordArray.random(length)),
                hashFunctions: {
                    SHA1: (data: Uint8Array) => {
                        let result: any = CryptoJS.SHA1(CryptoJS.lib.WordArray.create(data as any));
                        return wordArrayToBytes(result as any);
                    },
                    SHA256: (data: Uint8Array) => {
                        let result: any = CryptoJS.SHA256(CryptoJS.lib.WordArray.create(data as any));
                        return wordArrayToBytes(result as any);
                    },
                    SHA384: (data: Uint8Array) => {
                        let result: any = CryptoJS.SHA384(CryptoJS.lib.WordArray.create(data as any));
                        return wordArrayToBytes(result as any);
                    },
                    SHA512: (data: Uint8Array) => {
                        let result: any = CryptoJS.SHA512(CryptoJS.lib.WordArray.create(data as any));
                        return wordArrayToBytes(result as any);
                    },
                }
            };

        return this.mCrypto;
    }
}