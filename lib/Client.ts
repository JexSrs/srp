import {Routines} from "./modules/Routines";
import {ClientState} from "./components/ClientState";
import {M1AndA} from "./components/M1AndA";

export class Client {
    constructor(private readonly routines: Routines) {}

    private declare I: string
    private declare IH: ArrayBuffer
    private declare A: bigint
    private declare a: bigint
    private declare M1: bigint
    private declare S: bigint

    /**
     * Stores the user's identity and generates IH (Identity Hash) using the user's password.
     * @param identity User identity.
     * @param password User password (not kept in state).
     */
    step1(identity: string, password: string): void {
        if (!identity || !identity.trim()) throw new Error("User's identity (I) must not be null nor empty.");
        if (!password) throw new Error("User's password (P) must not be null");

        const IH = this.routines.computeIdentityHash(identity, password);

        this.I = identity;
        this.IH = IH;
    }

    /**
     * Generates public and private values A and a.
     * Generates Client evidence message M1 and session key S.
     * @param salt Salt received from server.
     * @param B Server public key "B".
     */
    step2(salt: string, B: string): M1AndA {
        if (!salt || !salt.trim()) throw new Error("Salt (s) must not be null nor empty.");
        if (!B || !B.trim()) throw new Error("Server's public value (B) must not be null nor empty.");

        let s = BigInt("0x" + salt);
        let Bbi = BigInt("0x" + B);

        const x = this.routines.computeXStep2(s, this.IH);
        const a = this.routines.generatePrivateValue();
        const A = this.routines.computeClientPublicValue(a);
        const k = this.routines.computeK();
        const u = this.routines.computeU(A, Bbi);
        const S = this.routines.computeClientSessionKey(k, x, u, a, Bbi);
        const M1 = this.routines.computeClientEvidence(this.I, s, A, Bbi, S);

        this.A = A;
        this.a = a;
        this.M1 = M1;
        this.S = S;

        return {M1: this.M1.toString(16), A: this.A.toString(16)};
    }

    /**
     * Checks if client and server is authenticated.
     * @param M2 Server message "M2".
     */
    step3(M2: string): void {
        if (!M2 || !M2.trim()) throw new Error("Server evidence (M2) must not be null nor empty.");

        let M2bi = BigInt("0x" + M2);

        const computedM2 = this.routines.computeServerEvidence(this.A, this.M1, this.S);
        if (computedM2 !== M2bi) throw new Error("Bad server credentials.");
    }

    /**
     * Exports identity, IH, A, a, M1 and S values.
     * Should be called after step1 or step2.
     */
    toJSON(): ClientState {
        let {I, IH, A, a, M1, S} = this;

        return {
            // filled after step1
            identity: I ? I : "",
            IH: IH ? Array.from(new Uint8Array(IH)) : [],

            // filled after step 2
            A: A ? A.toString(16) : "",
            a: a ? a.toString(16) : "",
            M1: M1 ? M1.toString(16) : "",
            S: S ? S.toString(16) : "",
        };
    }

    /**
     * Generates Client session from existing values: identity, IH, A, a, M1 and S.
     * @param routines The routines used when client session first generated.
     * @param state The state object, usually can be accessed from toJSON().
     */
    static fromState(routines: Routines, state: any) {
        let cl = new Client(routines);

        // filled after step1
        if(state.identity)
            cl.I = state.identity;
        if(state.IH)
            cl.IH = new Uint8Array(state.IH).buffer;

        // filled after step 2
        if(state.A)
            cl.A = BigInt("0x" + state.A);
        if(state.a)
            cl.a = BigInt("0x" + state.a);
        if(state.M1)
            cl.M1 = BigInt("0x" + state.M1);
        if(state.S)
            cl.S = BigInt("0x" + state.S);

        return cl;
    }
}