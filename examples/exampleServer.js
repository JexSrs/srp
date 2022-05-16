const {Server, Routines} = require('../dist');
const express = require('express');
const app = express();

app.use(express.json());

let db = {};
function getRoutines(primeNum, hash) {
    return {
        routines: new Routines(),
        hashFunction: Routines.Hash[hash],
        primeGroup: Routines.PrimeGroup[primeNum]
    };
}

const routines = getRoutines(2048, 'SHA512');

app.post('/register', function (req, res) {
    let {salt, verifier, username} = req.body;

    db = {identity: username, salt, verifier};
    res.status(200).end();
})

app.post('/login', function (req, res) {
    let {step, username, A, M1} = req.body;

    if(step === "1") {
        const server = new Server(routines);
        let user = db;
        if(!user) {
            // If user is not found send random, so we will not expose if the username exists
            res.status(200).send({
                salt: routines.generateRandomSalt().toString(16),
                B: routines.generatePrivateValue().toString(16)
            });
            return
        }

        const B = server.step1(username, user.salt, user.verifier); // Generate server's public key
        db = server.toJSON();

        /* respondToClient(B, salt) */
        res.status(200).send({salt: user.salt, B}); // Not json because we don't have a way to parse at java test (needs dependency)
    }
    else if(step === "2") {
        const server = new Server({
            ...routines,
            state: db
        });

        let M2;
        try {
            M2 = server.step2(A, M1); // Verify client (if exception, then failed)}
            res.status(200).send({M2});
        } catch (e) {
            console.log('User failed authentication')
            res.status(403).send(null);
        }
    }
    else {
        res.status(422).send(null);
        console.log(`Invalid step: ${step}`);
    }
});


const server = app.listen(5000, function () {
    let host = server.address().address
    let port = server.address().port

    console.log("Listening at https://%s:%s", host, port)
});
