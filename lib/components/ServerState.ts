export type ServerState = {
    identity: string;
    salt: string; // hex representation of bigint
    verifier: string;
    b: string;
    B: string;
}