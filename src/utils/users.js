const { retrieveEncryptedSeedAndSalt, storeNonceChiperAndSalt, retrieveNonceChiperAndSalt } = require('./storage.js')
const { generateKeyPairFromSeed, decryptSeed, encryptSeed, generateRandomSeed, mnemonicToSeed, seedToMnemonic } = require('./seed.js')
const Memory = require('./memory.js')
const { randomBytes } = require('hypercore-crypto')
const sodium = require('sodium-universal')

async function createUser ({ username, password }) {
  // Generate a random seed directly
  const seed = generateRandomSeed()

  // Encrypt the seed using the password and salt
  const salt = randomBytes(sodium.crypto_pwhash_SALTBYTES)
  const nonceAndChiper = encryptSeed(seed, password, salt)

  // Store the encrypted seed and salt securely with the username as the identifier
  await storeNonceChiperAndSalt(username, { ...nonceAndChiper, salt })

  // Generate the key pair from the seed
  const keyPair = generateKeyPairFromSeed(seed)

  // Convert seed to a mnemonic phrase for user (for backup)
  const mnemonic = seedToMnemonic(seed)

  Memory.initialize({ username, keyPair, seed })

  return { mnemonic, keyPair, seed }
}

async function restoreUser ({ seedPhrase, username, password }) {
  // Convert seed phrase to seed
  const seed = mnemonicToSeed(seedPhrase)

  // Encrypt the seed using the password and salt
  const salt = randomBytes(sodium.crypto_pwhash_SALTBYTES)
  const nonceAndChiper = encryptSeed(seed, password, salt)

  // Store the encrypted seed and salt securely with the username as the identifier
  await storeNonceChiperAndSalt(username, { ...nonceAndChiper, salt })

  // Generate the key pair from the seed
  const keyPair = generateKeyPairFromSeed(seed)

  Memory.initialize({ username, keyPair, seed })

  return keyPair
}

async function authUser ({ username, password }) {
  try {
    // Retrieve the encrypted seed and salt for the username
    const { nonce, ciphertext, salt } = await retrieveNonceChiperAndSalt(username)
    if (!ciphertext || !salt) {
      throw new Error('Username not found or missing data.')
    }

    // Decrypt the seed using the password and salt
    const seed = decryptSeed({ nonce, ciphertext, salt, password })

    // Generate the key pair from the seed
    const keyPair = generateKeyPairFromSeed(seed)

    Memory.initialize({ username, keyPair, seed })

    // If keyPair is successfully generated, the user is authenticated
    return { username, keyPair, seed }
  } catch (error) {
    console.log(error)
    return null
  }
}

async function usernameExists (username) {
  const response = await retrieveEncryptedSeedAndSalt(username)
  return response.code !== 404
}

module.exports = {
  usernameExists,
  createUser,
  restoreUser,
  authUser
}
