import test from 'brittle'
import { createUser, authUser, restoreUser } from '../src/utils/users.js'
import { validateKeyPair } from 'hypercore-crypto'
import { validateMnemonic } from 'bip39'
import { validateSeed } from '../src/utils/seed.js'

test('create, authenticate, and restore user flow', async (t) => {
  const username = 'testuser'
  const password = 'testpassword'

  // Step 1: Create User
  const createdUser = await createUser({ username, password })
  t.ok(createdUser.mnemonic, 'Mnemonic should be generated')
  t.ok(validateMnemonic(createdUser.mnemonic), 'Mnemonic should be valid')
  t.ok(createdUser.keyPair, 'Key pair should be generated')
  t.ok(createdUser.seed, 'Seed should be generated')
  t.ok(validateSeed(createdUser.seed), 'Seed should be valid')
  t.ok(validateKeyPair({
    publicKey: createdUser.keyPair.publicKey,
    secretKey: createdUser.keyPair.secretKey
  }), 'Created users key pair should be valid')

  // Step 2: Authenticate User
  const authenticatedUser = await authUser({ username, password })
  t.ok(authenticatedUser, 'User should be authenticated')
  t.alike(authenticatedUser.keyPair, createdUser.keyPair, 'Key pairs should match for authenticated user')
  t.ok(validateKeyPair({
    publicKey: authenticatedUser.keyPair.publicKey,
    secretKey: authenticatedUser.keyPair.secretKey
  }), 'Authenticated key pair should be valid')
  t.ok(validateSeed(authenticatedUser.seed), 'Authenticated seed should be valid')
  t.is(authenticatedUser.seed, createdUser.seed, 'Seeds should match for authenticated user')

  // Step 3: Restore User
  const restoredUser = await restoreUser({ seedPhrase: createdUser.mnemonic, username, password })
  t.ok(restoredUser, 'User should be restored')
  t.alike(restoredUser, createdUser.keyPair, 'Key pairs should match for restored user')
  t.ok(validateKeyPair(restoredUser), 'Restored key pair should be valid')
})
