import {Server, ServerState} from "./server";
import {Client} from "./client";
import { Routines } from "./modules/Routines";
import {Parameters} from "./modules/Parameters";
import { ClientState } from "./components/ClientState";
import {createVerifierAndSalt} from "./modules/utils";
import {VerifierAndSalt} from "./components/VerifierAndSalt";

export function generateVerifierAndSalt(routines: Routines, I: string, P: string, sBytes?: number): VerifierAndSalt {
    let {verifier, salt} = createVerifierAndSalt(routines, I, P, sBytes)

    return {
        verifier: verifier.toString(16),
        salt: salt.toString(16)
    }
}

export {Server, ServerState, Client, ClientState, Routines, Parameters};