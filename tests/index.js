const {Server, Client, Routines, Parameters, generateVerifierAndSalt} = require('../dist');


setTimeout(() => {
    console.log('Timeout was reached.');
    process.exit(1);
}, 20000); // 40 sec

let db = [];

// Registration
(() => {
    // Client
    const username = "projectChristopher";
    const password = "password";

    let routines = new Routines(new Parameters());
    let {salt, verifier} = generateVerifierAndSalt(routines, username, password);
    /* sendToServer(username, salt, verifier) */

    // Server
    /* storeToDatabase(username, salt, verifier) */
    db.push({username, salt, verifier});
})();

// Login
(() => {
    // Client
    const username = "projectChristopher";
    let password = "password";

    const client = new Client(new Routines(new Parameters()));
    client.step1(username, password);
    password = ''; // No longer needed.
    /* sendToServer(username) */

    // Server
    const server = new Server(new Routines(new Parameters()));
    let document = db.find(doc => doc.username === username);
    if(!document) {
        // Send random data to avoid if user exists
        /* respondToClient(randomB, randomSalt) */
        return;
    }

    let salt = document.salt
    const B = server.step1(username, salt, document.verifier); // Generate server's public key
    /* respondToClient(B, salt) */

    // Client
    let {A, M1} = client.step2(salt, B); // Generate client's public key A and client (M1) evidence.
    /* sendToServer(A, M1) */

    // Server
    let M2 = server.step2(A, M1); // Verify client (if exception, then failed)
    /* respondToClient(M2) */

    // Client
    client.step3(M2); // Verify server (if exception, then failed)

    process.exit(0);
})();