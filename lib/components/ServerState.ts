export type ServerState = {
    identity: string;
    salt: string; // hex representation of bigint
    verifier: string;
    B: string;
    b: string;
}