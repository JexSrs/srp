export const ZERO: bigint = BigInt(0);
export const ONE: bigint = BigInt(1);
export const TWO: bigint = BigInt(2);

/**
 * Calculates (x**pow) % mod
 * @param x base, non negative big int.
 * @param pow power, non negative power.
 * @param mod modulo, positive modulo for division.
 */
export function modPow(x: bigint, pow: bigint, mod: bigint): bigint {
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