import {CompatibleCrypto} from "../components/CompatibleCrypto";


export class Crypto {

    private static mCrypto?: CompatibleCrypto = undefined;

    static compatibleCrypto(): CompatibleCrypto {
        if(!this.mCrypto) {
            const nodeCrypto = require("crypto");
            const nodeCreateHashToHashFunction = (algorithm: AlgorithmIdentifier) =>
                (data: Uint8Array) => nodeCrypto.createHash(algorithm).update(data).digest().buffer;

            this.mCrypto = {
                randomBytes: (length: number) => nodeCrypto.randomFillSync(new Uint8Array(length)),
                hashFunctions: {
                    SHA1: (data: Uint8Array) => nodeCreateHashToHashFunction("sha1")(data),
                    SHA256: (data: Uint8Array) => nodeCreateHashToHashFunction("sha256")(data),
                    SHA384: (data: Uint8Array) => nodeCreateHashToHashFunction("sha384")(data),
                    SHA512: (data: Uint8Array) => nodeCreateHashToHashFunction("sha512")(data),
                }
            };
        }

        return this.mCrypto;
    }
}