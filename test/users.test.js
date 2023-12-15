import test from 'brittle'
import { createUser, authUser, restoreUser } from '../src/utils/users.js'
import { validateKeyPair } from 'hypercore-crypto'
import { validateMnemonic } from 'bip39'
import { validateSeed } from '../src/utils/seed.js'
import { Memory } from '../src/utils/memory.js'

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

  // Testing the memory
  t.ok(Memory.getKeyPair(), 'Key pair should be set after auth')
  t.ok(Memory.getKeyPair('pubkey'), 'Public key should be set after auth')
  t.ok(Memory.getKeyPair('secretKey'), 'Secret key should be set after auth')
  t.ok(Memory.getSeed(), 'Seed should be set after auth')

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

  // Testing the memory
  t.alike(Memory.getKeyPair('publicKey'), authenticatedUser.keyPair.publicKey, 'Public key should match')
  t.alike(Memory.getKeyPair('secretKey'), authenticatedUser.keyPair.secretKey, 'Secret key should match')
  t.alike(Memory.getSeed(), authenticatedUser.seed, 'Seed should match')

  // Step 3: Restore User
  const restoredUser = await restoreUser({ seedPhrase: createdUser.mnemonic, username, password })
  t.ok(restoredUser, 'User should be restored')
  t.alike(restoredUser, createdUser.keyPair, 'Key pairs should match for restored user')
  t.ok(validateKeyPair(restoredUser), 'Restored key pair should be valid')
})
