import {HashFunction, PrimeGroup} from "./cryptoTypes";
import {Routines} from "../modules/routines";
import {ClientState, ServerState} from "./types";

export type Options = {
    primeGroup: PrimeGroup;
    hashFunction: HashFunction;
    routines: Routines;
    srvState?: ServerState;
    clientState?: ClientState;
};