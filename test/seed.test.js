const test = require('brittle')
const sodium = require('sodium-universal')
const { generateKeyPairFromSeed, generateEncryptionKeyFromKeyPair, generateChildKeyPair, encryptSeed, decryptSeed } = require('../src/utils/seed.js')
const { keyPair, randomBytes } = require('hypercore-crypto')
const { createUser } = require('../src/utils/users.js')
const { generateKeyPairFromMnemonic } = require('../src/utils/mnemonic.js')

process.env.OPSLIMIT = sodium.crypto_pwhash_OPSLIMIT_MIN
process.env.MEMLIMIT = sodium.crypto_pwhash_MEMLIMIT_MIN

async function createUsers () {
  const userA = await createUser({ username: 'testA', password: 'password' })
  const userB = await createUser({ username: 'testB', password: 'password' })

  return { userA, userB }
}

// Tests for generateKeyPairFromSeed
test('generateKeyPairFromSeed with string seed', async (t) => {
  const seed = Buffer.allocUnsafe(32).fill('test')
  const keyPair = generateKeyPairFromSeed(seed)

  t.is(keyPair.publicKey.length, 32)
  t.is(keyPair.secretKey.length, 64)
})

test('generateKeyPairFromSeed with buffer seed', async (t) => {
  const seed = Buffer.allocUnsafe(32).fill('test')
  const keyPair = generateKeyPairFromSeed(seed)

  t.is(keyPair.publicKey.length, 32)
  t.is(keyPair.secretKey.length, 64)
})

// Test with a valid mnemonic
test('generateKeyPairFromMnemonic with valid mnemonic', async (t) => {
  const validMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
  const keyPair = generateKeyPairFromMnemonic(validMnemonic)

  t.ok(keyPair.publicKey && keyPair.secretKey, 'Should return a key pair with public and secret keys')
  t.is(keyPair.publicKey.length, 32)
  t.is(keyPair.secretKey.length, 64)
})

// Test with an invalid mnemonic
test('generateKeyPairFromMnemonic with invalid mnemonic', async (t) => {
  const invalidMnemonic = 'invalid mnemonic'

  try {
    generateKeyPairFromMnemonic(invalidMnemonic)
    t.fail('Should have thrown an error or returned an invalid key pair')
  } catch (error) {
    t.pass('Expected error thrown or invalid key pair returned')
  }
})

test('generateEncryptionKeyFromKeyPair', async (t) => {
  const key = keyPair()
  const encryptionKey = generateEncryptionKeyFromKeyPair(key)

  t.ok(encryptionKey, 'Should return an encryption key')
  t.is(encryptionKey.length, 32, 'Encryption key should be 32 bytes long')
  t.alike(encryptionKey, generateEncryptionKeyFromKeyPair(key), 'Should produce the same encryption key for the same key pair')
  t.unlike(encryptionKey, generateEncryptionKeyFromKeyPair(keyPair()), 'Should produce different encryption key for a diff key pair')
})

// Consistency test for the same seed and path
test('generateChildKeyPair generates consistent key pairs for the same seed and path', async (t) => {
  const { userA } = await createUsers()
  const path = "m/0'/1/0" // A specific path

  const childKeyPair1 = generateChildKeyPair(userA.seed, path)
  const childKeyPair2 = generateChildKeyPair(userA.seed, path)

  t.alike(childKeyPair1, childKeyPair2, 'Should generate the same child key pair for the same seed and path')
})

// Test for different seeds
test('generateChildKeyPair generates different key pairs for different seeds', async (t) => {
  const { userA, userB } = await createUsers()
  const path = "m/0'/1/0"

  const childKeyPair1 = generateChildKeyPair(userA.seed, path)
  const childKeyPair2 = generateChildKeyPair(userB.seed, path)

  t.unlike(childKeyPair1, childKeyPair2, 'Should generate different child key pairs for different seeds')
})

// Test for different paths
test('generateChildKeyPair generates different key pairs for different paths', async (t) => {
  const { userA } = await createUsers()
  const path1 = "m/0'/1/0"
  const path2 = "m/0'/1/1"

  const childKeyPair1 = generateChildKeyPair(userA.seed, path1)
  const childKeyPair2 = generateChildKeyPair(userA.seed, path2)

  t.unlike(childKeyPair1, childKeyPair2, 'Should generate different child key pairs for different paths')
})

test('decryptSeed correctly decrypts an encrypted seed', async (t) => {
  const seed = '1234567890abcdef1234567890abcdef'
  const password = 'strongpassword'
  const salt = randomBytes(16)

  // Encrypt the seed first
  const { nonce, ciphertext } = encryptSeed(seed, password, salt)

  // Decrypt the seed
  // const decryptedSeed = decryptSeed(iv, encryptedSeed, authTag, password, salt)
  const decryptedSeed = decryptSeed({ nonce, ciphertext, salt, password })

  t.is(decryptedSeed, seed, 'Decrypted seed should match the original seed')
})
