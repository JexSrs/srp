import {Routines} from "./modules/routines";
import {ServerState} from "./components/types";
import {Options} from "./components/options";

export class Server {

    private readonly routines: Routines;

    private declare I: string;
    private declare salt: bigint;
    private declare verifier: bigint;
    private declare b: bigint;
    private declare B: bigint;

    constructor(options?: Partial<Options>) {
        let opts: any = options || {};
        this.routines = (opts.routines || new Routines()).apply(opts);

        if(opts.srvState) {
            this.I = opts.srvState.identity;
            this.salt = BigInt("0x" + opts.srvState.salt);
            this.verifier = BigInt("0x" + opts.srvState.verifier);
            this.b = BigInt("0x" + opts.srvState.b);
            this.B = BigInt("0x" + opts.srvState.B);
        }
    }

    /**
     * Stores identity, salt and verifier.
     * Generates public and private keys "B" and "b".
     * @param identity User's identity.
     * @param salt Salt stored in database.
     * @param verifier Verifier stored in database.
     * @return B Server's public key.
     */
    public step1(identity: string, salt: string, verifier: string): string {
        if (!identity || !identity.trim()) throw new Error("Identity must not be null nor empty.");
        if (!salt || !salt.trim()) throw new Error("Salt must not be null nor empty.");
        if (!verifier || !verifier.trim()) throw new Error("Verifier must not be null nor empty.");

        let v = BigInt("0x" + verifier)

        const b = this.routines.generatePrivateValue();
        const k = this.routines.computeK();
        const B = this.routines.computeServerPublicValue(k, v, b);

        this.I = identity;
        this.salt = BigInt("0x" + salt);
        this.verifier = v;
        this.b = b;
        this.B = B;

        return this.B.toString(16);
    }

    /**
     * Compute the server session key "S".
     * @param A Client public key "A".
     */
    sessionKey(A: bigint): bigint {
        if (A === null) throw new Error("Client public value (A) must not be null.");

        if (!this.routines.isValidPublicValue(A))
            throw new Error(`Invalid Client public value (A): ${A.toString(16)}`);

        const u = this.routines.computeU(A, this.B);

        // S
        return this.routines.computeServerSessionKey(this.verifier, u, A, this.b);
    }

    /**
     * Computes M2 and checks if client is authenticated.
     * @param A Client public key "A"
     * @param M1 Client message "M1".
     * @return The server evidence message "M2".
     */
    step2(A: string, M1: string): string {
        if (!A || !A.trim()) throw new Error("Client public key (A) must not be null nor empty.");
        if (!M1 || !M1.trim()) throw new Error("Client evidence (M1) must not be null nor empty.");

        let Abi = BigInt("0x" + A);
        let M1bi = BigInt("0x" + M1);

        const S = this.sessionKey(Abi);

        const computedM1 = this.routines.computeClientEvidence(this.I, this.salt, Abi, this.B, S);
        if (computedM1 !== M1bi) throw new Error("Bad client credentials.");

        // M2
        return this.routines.computeServerEvidence(Abi, M1bi, S).toString(16);
    }

    /**
     * Exports "identity", "salt", "verifier" values and "b", "B" keys.
     * Should be called after step1.
     */
    toJSON(): ServerState {
        return {
            identity: this.I,
            salt: this.salt.toString(16),
            verifier: this.verifier.toString(16),
            b: this.b.toString(16),
            B: this.B.toString(16),
        };
    }
}