const expect = require('chai').expect;
const {Server, Client, Routines, generateRandomString} = require('../dist');
const {generateVerifierAndSalt} = require("../dist");

const primeNums = [256, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192];
const hashes = ['SHA1', 'SHA256', 'SHA384', 'SHA512'];

function getOptions(primeNum, hash) {
    return {
        routines: new Routines(),
        hashFunction: Routines.Hash[hash],
        primeGroup: Routines.PrimeGroup[primeNum]
    };
}

describe('Parameters', function () {
    for (let primeNum of primeNums) {
        let timeout = primeNum === 8192 ? 10000 : 2000;
        timeout = primeNum === 6144 ? 5000 : timeout;
        timeout = primeNum < 4096 ? 2000 : timeout;
        this.timeout(timeout);

        for (let hash of hashes) {
            it(`Prime: ${primeNum}, Hash: ${hash}`, () => {
                let options = getOptions(primeNum, hash);

                const identity = generateRandomString(16);
                const password = generateRandomString(16);

                let {salt, verifier} = generateVerifierAndSalt(options, identity, password);

                const client = new Client(options);
                client.step1(identity, password);

                const server = new Server(options);
                const B = server.step1(identity, salt, verifier);

                const {A, M1} = client.step2(salt, B);
                let M2 = server.step2(A, M1);

                client.step3(M2);
            });
        }
    }
});

describe('Wrong password', function () {
    this.timeout(4000);

    for (let i = 1; i <= 20; i++) {
        it(`Test ${i}`, () => {
            let options = getOptions(2048, 'SHA512'); // Default

            const identity = generateRandomString(16);
            const password = generateRandomString(16);
            const falsePassword = `false${password}`;

            let {salt, verifier} = generateVerifierAndSalt(options, identity, password);

            const client = new Client(options);
            client.step1(identity, falsePassword);

            const server = new Server(options);
            const B = server.step1(identity, salt, verifier);

            const {A, M1} = client.step2(salt, B);

            expect(() => server.step2(A, M1)).to.throw();

        });
    }
});
