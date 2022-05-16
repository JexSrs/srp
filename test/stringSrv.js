const {Server, Routines, Parameters} = require('../dist');
const express = require('express');
const app = express();

app.use(express.json());

let db = {};

function getRoutines(primeNum, hash) {
    return new Routines({
        hashFunction: Routines.Hash[hash],
        primeGroup: Routines.PrimeGroup[primeNum]
    });
}

app.post('/register', function (req, res) {
    console.log("=== Register open ===")
    let {salt, verifier, username} = JSON.parse(Object.keys(req.body)[0]);

    db = {username, salt, verifier}
    res.status(200).send("ok!");
    console.log("All good");
    console.log("=== Register close ===")
})

app.post('/login', function (req, res) {
    console.log("=== Login open ===")
    let {step, username, A, M1} = JSON.parse(Object.keys(req.body)[0]);

    if(step === "1") {
        const server = new Server(getRoutines(2048, 'SHA256'));
        let user = db;
        if(!user) {
            res.status(200).send("failed!");
            return
        }

        const B = server.step1(username, user.salt, user.verifier); // Generate server's public key
        db = server.toJSON();

        /* respondToClient(B, salt) */
        res.status(200).send(user.salt + "-salt-B-" + B); // Not json because we don't have a way to parse at java test (needs dependency)
        console.log("All good 1");
    }
    else if(step === "2") {
        const server = Server.fromState(getRoutines(2048, 'SHA256'), db);
        let M2 = server.step2(A, M1); // Verify client (if exception, then failed)

        res.status(200).send(M2);
        console.log("All good 2");
    }
    else console.log(`Invalid step: ${step}`);
    console.log("=== Login close ===")
});


// const server = app.listen(5000, function () {
//     let host = server.address().address
//     let port = server.address().port
//
//     console.log("Listening at https://%s:%s", host, port)
// });
