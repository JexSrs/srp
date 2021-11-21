export type ClientState = {
    identity: string;
    IH: Array<number>; // standard Array representation of the Uint8Array ArrayBuffer
    A: string; // hex representation of bigint
    a: string;
    M1: string;
    S: string;
}