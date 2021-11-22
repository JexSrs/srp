/**
 * Convert a BigInteger into ArrayBuffer.
 * @param n Any big integer.
 */
export function bigintToArrayBuffer(n: bigint): ArrayBuffer {
    const hex = n.toString(16);
    const arrayBuffer = new ArrayBuffer(Math.ceil(hex.length / 2));
    const u8 = new Uint8Array(arrayBuffer);
    let offset = 0;
    // handle toString(16) not padding
    if (hex.length % 2 !== 0) {
        u8[0] = parseInt(hex[0], 16);
        offset = 1;
    }
    for (let i = 0; i < arrayBuffer.byteLength; i++) {
        u8[i + offset] = parseInt(
            hex.slice(2 * i + offset, 2 * i + 2 + offset),
            16,
        );
    }
    return arrayBuffer;
}

/**
 * Convert an ArrayBuffer into BigInteger.
 * @param ab The ArrayBuffer.
 */
export function arrayBufferToBigint(ab: ArrayBuffer): bigint {
    const hex: string[] = [];
    // we can't use map here because map will return Uint8Array which will screw up the parsing below
    new Uint8Array(ab).forEach((i) => {
        hex.push(("0" + i.toString(16)).slice(-2)); // i.toString(16) will transform 01 to 1, so we add it back on and slice takes the last two chars
    });
    return BigInt(`0x${hex.join("")}`);
}

/**
 * Convert string into ArrayBuffer.
 * @param s Any UTF8 string.
 */
export function stringToArrayBuffer(s: string): ArrayBuffer {
    return new TextEncoder().encode(s).buffer;
}