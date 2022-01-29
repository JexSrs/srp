/**
 * Convert a bigint into byte array.
 * @param n
 */
export function bigintToBytes(n: bigint): Uint8Array {
    const hex = n.toString(16);
    const u8 = new Uint8Array(Math.ceil(hex.length / 2));
    let offset = 0;
    // handle toString(16) not padding
    if (hex.length % 2 !== 0) {
        u8[0] = parseInt(hex[0], 16);
        offset = 1;
    }
    for (let i = 0; i < u8.byteLength; i++) {
        u8[i + offset] = parseInt(
            hex.slice(2 * i + offset, 2 * i + 2 + offset),
            16,
        );
    }
    return u8;
}

/**
 * Convert bytes array to bigint.
 * @param array
 */
export function bytesToBigint(array: Uint8Array): bigint {
    const hex: string[] = [];
    // we can't use map here because map will return Uint8Array which will screw up the parsing below
    new Uint8Array(array).forEach((i) => {
        hex.push(("0" + i.toString(16)).slice(-2)); // i.toString(16) will transform 01 to 1, so we add it back on and slice takes the last two chars
    });
    return BigInt(`0x${hex.join("")}`);
}

/**
 * Convert string into byte array.
 * @param str Any UTF8 string.
 */
export function stringToByteArray(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}