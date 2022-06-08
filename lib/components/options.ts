import {HashFunction, PrimeGroup} from "./cryptoTypes";
import {Routines} from "../modules/routines";

export type Options = {
    primeGroup: PrimeGroup;
    hashFunction: HashFunction;
    routines: Routines;
};