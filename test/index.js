const expect = require('chai').expect;
const {Server, Client, Routines, Parameters, generateVerifierAndSalt, generateRandomString} = require('../dist');

const primeNums = [256, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192];
const hashes = ['SHA1', 'SHA256', 'SHA384', 'SHA512'];

function getRoutines(primeNum, hash) {
    return new Routines(new Parameters(Parameters.PrimeGroup[primeNum], Parameters.Hash[hash]));
}

describe('Parameters', function () {
    for (let primeNum of primeNums) {
        let timeout = primeNum === 8192 ? 10000 : 2000;
        timeout = primeNum === 6144 ? 5000 : timeout;
        timeout = primeNum < 4096 ? 2000 : timeout;
        this.timeout(timeout);

        for (let hash of hashes) {
            it(`Prime: ${primeNum}, hash: ${hash}`, () => {
                let routines = getRoutines(primeNum, hash);

                const identity = generateRandomString(16);
                const password = generateRandomString(16);

                let {salt, verifier} = generateVerifierAndSalt(routines, identity, password);

                const client = new Client(routines);
                client.step1(identity, password);

                const server = new Server(routines);

                const B = server.step1(identity, salt, verifier);

                const {A, M1} = client.step2(salt, B);

                let M2 = server.step2(A, M1);

                client.step3(M2);
            });
        }
    }
});

describe('Wrong password', function () {
    this.timeout(2000);

    for (let i = 1; i <= 10; i++) {
        it(`Test ${i}`, () => {
            let routines = getRoutines(2048, 'SHA512'); // Default

            const identity = generateRandomString(16);
            const password = generateRandomString(16);
            const falsePassword = `false${password}`;

            let {salt, verifier} = generateVerifierAndSalt(routines, identity, password);

            const client = new Client(routines);
            client.step1(identity, falsePassword);

            const server = new Server(routines);
            const B = server.step1(identity, salt, verifier);

            const {A, M1} = client.step2(salt, B);

            expect(() => server.step2(A, M1)).to.throw();

        });
    }
});
