# p2p-auth
p2p-auth is a Node.js library providing secure user authentication and key management functionalities. It leverages cryptographic techniques for seed generation and encryption, based on the principles of BIP32 (Hierarchical Deterministic Wallets) and BIP39 (Mnemonic Code for Generating Deterministic Keys).

----

# Features
- **Create User:** Generate and store user credentials locally with encryption, following BIP32 and BIP39 standards for seed generation and mnemonic phrase creation.
- **Restore User:** Restore user access from a mnemonic seed phrase, compatible with BIP39.
- **Authenticate User:** Validate user credentials and provide access to the encrypted seed

# Examples
```javascript
// Create user
// This stores the encrypted seed into the local directory.
const { mnemonic, keyPair, seed } = await createUser({ username, password });
console.log('You can restore the user using the seed phrase:', mnemonic);

// Restore user
// "seedPhrase" should be the "mnemonic" from the above.
// "username" and "password" are used to store the seed into the local directory similarly to when you "createUser".
await restoreUser({ seedPhrase, username, password });

// Auth user
// It tries to find the user based on the given username from the directory
// and decrypt the seed based on the given password.
const { keyPair, seed } = await authUser({ username, password });

// Create a new child key pair from master keys
const childKeyPair = generateChildKeyPair(seed, "m/0'/1/1");
```


------


# CLI
You can import the `authCLI` function into your CLI application and call it using `await authCLI()` to provide an interactive authentication process. For example:
```javascript
const startCLI = async () => {
    const { username, keyPair, seed } = await authCLI()

    program
        .command('something')
        .description('Do something with the authenticated user')
        .action(doSomething)
}

startCLI().catch(error => console.error(error))
```
