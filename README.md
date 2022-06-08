# Secure Remote Password
**SRP | Safe authentication without password exchange**

This is a TypeScript implementation of Secure Remote Password as documented at RFC5054.

The part of using steps was inspired by [tssrp6a](https://github.com/midonet/tssrp6a) which is another SRP implementation,
but it was asynchronous. Anyway, we thank you.

## Installation
```shell
# Add repository as dependency 
```

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

### Credentials
The user's credentials that will be used for registration and authentication.
```javascript
const username = "JexSrs";
let password = "pass123";
```

### Registration
This flow will register a new user to the server.

```javascript
import {Server, Client, Routines, generateVerifierAndSalt} from "srp";

const {salt, verifier} = generateVerifierAndSalt(getOptions(), identity, password);
sendToServer(username, salt, verifier);

// Server
storeToDatabase(username, salt, verifier);
```

### Login
This flow will verify a user that has registered using the above flow.
__Caution!__ If the options used during registration are different from the ones used during authentication,
the authentication will always fail.

#### Step 1
In this step we will initialize client with user's credentials and request from server a generated
public value (B) and the salt that was given during registration.

```javascript
// Client
const client = new Client(options);
client.step1(identity, password);
password = ''; // No longer needed.
sendToServer(username);

// Server
const server = new Server(options);
let doc = getFromDatabase(identity);
if(doc == null) {
    // Send random data to avoid exposing if user exists
    respondToClient(randomB, randomSalt);
    return;
}

let salt = doc.salt
const B = server.step1(identity, salt, doc.verifier); // Generate server's public key
saveToCache(server.toJSON()); // Maybe a redis or database
respondToClient(B, salt);
```

#### Step 2
In this step the client has received the public value (B) and salt from the server.
The client will now generate a public value (A) and the evidence message (M1) and send it to server
to authenticate itself.

```javascript
// Client
const {A, M1} = client.step2(salt, B);
sendToServer(A, M1);

// Server
let doc = getFromCache(username)
if(doc == null)
    return sendToClient('Authentication failed');

let server = new Server(options, doc); // Init with state

let M2;
try {
    M2 = server.step2(A, M1);
} catch(e) {
    return sendToClient('Authentication failed');
}

respondToClient(M2);
```

#### Step 3
In step 3 the client has received the server's evidence message (M2) and will verify that the server is
the same as the one that started the authentication.

```javascript
// Client
try {
    client.step3(M2);
} catch (e) {
    // Server is not the one we started.
}
```

## Options
### PrimeGroup
Default value: `2048`

Available values: `256`, `512`, `768`, `1024`, `1536`, `2048`, `3072`, `4096`, `6144`, `8192`

### HashFunction
Default value: `SHA512`

Available values: `SHA1`, `SHA256`, `SHA384`, `SHA512`

### Routines
Tou can always implement different routines by extending the routines class.

### Server State
Initialize server using an older state. This can be when authenticating with HTTP protocol.

### Client State
Initialize client using an older state.


