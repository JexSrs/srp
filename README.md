# Secure Remote Password
**SRP | Safe authentication without password exchange**

This is a TypeScript implementation of Secure Remote Password as documented at [RFC5054](https://datatracker.ietf.org/doc/html/rfc5054).

The part of using steps was inspired by [tssrp6a](https://github.com/midonet/tssrp6a) which is another SRP implementation,
but it was asynchronous. Anyway, we thank you. 


## How to use?

### Options
The options that will be created here, will be used from both server and client.
Take caution that different options will generate different values, so there will be no compatibility.

```javascript
const options = {
    routines: new Routines(), // This is the default and can be ommited. You can write your own routines by inheriting the routines clss
    hashFunction: Routines.Hash['SHA256'],
    primeGroup: Routines.PrimeGroup[2048]
};
```

### Registration

```javascript
import {Server, Client, Routines} from "@project-christopher/srp";

// Client
const identity = "projectChristopher";
const password = "password";

const {salt, verifier} = Client.register({...options, identity, password});
/* sendToServer(username, salt, verifier) */

// Server
/* storeToDatabase(username, salt, verifier) */
```

### Login
```javascript
import {Server, Client, Routines, Parameters} from "@project-christopher/srp";

// Client
const identity = "projectChristopher";
let password = "password";

const client = new Client(options);
client.step1(identity, password);
password = ''; // No longer needed.
/* sendToServer(identity) */

// Server
const server = new Server(options);
/* let doc = getFromDatabase(identity) */
if(!doc) {
    // Send random data to avoid exposing if user exists.
    /* sendToClient(randomB, randomSalt) */
    return;
}

let salt = doc.salt
const B = server.step1(identity, salt, doc.verifier); // Generate server's public key
/* sendToClient(B, salt) */

// Client
const {A, M1} = client.step2(salt, B); // Generate client's public key A and client (M1) evidence.
/* sendToServer(A, M1) */

// Server
/* const doc = getFromDatabase(identity) */
let server2 = new Server({...routines, srvState: doc});
let M2 = server.step2(A, M1); // Verify client (if exception, then failed)
/* sendToClient(M2) */

// Client
client.step3(M2); // Verify server (if exception, then failed)
```


For the full documentation visit the [docs](https://project-christopher.com/docs/srp/installation).
