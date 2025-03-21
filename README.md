# Signature Verification API Example

Hi and thanks for finding my project 👋😀

## What is it?

This is a project to demonstrate a web service that proves ownership of a private key using Rust. Here are the basic concepts:
* Two actors are involved: a holder, and a verifier web service.
    * The holder is a script that signs a payload with the private key and calls the verifier API with the public key.
    * The verifier is a Rust/Axum API that verifies the payload and signature using the public key to establish that the holder controls the private key.
* A [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) is used to prevent replay of attestations.

## How do I use it?

### Dependencies
* `cargo`
* `openssl`
* `curl`
* `jq`
* `lsof`

### Instructions
You will need 2 terminal emulator windows/tabs.
1. In the first terminal, run this to start the Rust API.:
```bash
cargo run
```
2. In the second, run this which will create the keys, sign a message, and send a json payload to the Rust API for verification:
```bash
./sign_and_verify.sh "My message here"
```

You will see the results after. You can use whatever you like for the message. If you do something wrong when running the script, it will probably tell you.

### Running Tests
You can use the following command to run tests:
```bash
cargo test
```

## How does it work?

### Request Payload
The Rust API listens for incoming requests on `localhost:3000` only (this is a demo, so [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS) is configured to only allow requests from `localhost`). It uses the following payload schema for requests:
```json
{
    "message": <string>,
    "public_key": <string>,
    "signature": <string>
}
```

Here are a couple notes about the payload:
* The signature is expected to be 64-bit encoded before being sent in the payload.
* The message is expected to have exactly 2 sections delimited by a ":nonce:" string. To the left is the nonce, to the right is the message's payload, which can be any 64-bit encoded string. An example message might look like this: "7925883:nonce:my message here"
    * The nonce is recommended to be a random or pseudo-random number. I like concatenating a date with a random number so even if my random number is the same as a previous run, it's very unlikely that it will happen at the same second (or millisecond, depending on how much detail I include in my timestamp).

### Server Internals
1. Once the data is received by the API, it validates the json message with a schema.
2. It then parses the `message` field for the nonce and checks if that nonce has been used in the past. In this example, I use a hash map, but in a more serious project, a database should be used for persistent storage.
3. Next, it decodes the signature.
4. Finally, it uses the message and public key to verify the cryptographic signature with OpenSSL and return the results.

### Response Payload
The response will look the same every time:
```json
{
  "valid": <bool>,
  "message": <string>
}
```

The `valid` field will be `true` if the signature is valid and `false` otherwise. The `message` field will hold more details about the response, including what went wrong, if something did.
