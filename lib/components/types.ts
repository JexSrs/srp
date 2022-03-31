export type ClientState = {
    identity: string;
    IH: Array<number>; // standard Array representation of the Uint8Array
    A: string; // hex representation of bigint
    a: string;
    M1: string;
    S: string;
};

export type ServerState = {
    identity: string;
    salt: string; // hex representation of bigint
    verifier: string;
    B: string;
    b: string;
};

export type M1AndA = {
    A: string;
    M1: string;
};

export type IVerifierAndSalt = {
    salt: string;
    verifier: string;
};