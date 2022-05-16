export type ClientState = {
    identity: string;
    IH: Array<number>;
    A: string;
    a: string;
    M1: string;
    S: string;
};

export type ServerState = {
    identity: string;
    salt: string;
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