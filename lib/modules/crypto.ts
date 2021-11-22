import {CompatibleCrypto} from "../components/CompatibleCrypto";

export class Crypto {

    /**
     * Returns the compatible crypto for this system.
     */
    static compatibleCrypto(): CompatibleCrypto {
        const nodeCrypto = require("crypto");
        const nodeCreateHashToHashFunction = (algorithm: AlgorithmIdentifier) => (data: ArrayBuffer) =>
            nodeCrypto.createHash(algorithm).update(data).digest().buffer;

        return {
            randomBytes: nodeCrypto.randomFillSync,
            hashFunctions: {
                SHA1: nodeCreateHashToHashFunction("sha1"),
                SHA256: nodeCreateHashToHashFunction("sha256"),
                SHA384: nodeCreateHashToHashFunction("sha384"),
                SHA512: nodeCreateHashToHashFunction("sha512"),
            }
        };
    }
}