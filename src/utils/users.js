const crypto = require('crypto')
const { retrieveEncryptedSeedAndSalt, storeEncryptedSeedAndSalt } = require('./storage.js')
const { generateKeyPairFromSeed, decryptSeed, encryptSeed, generateRandomSeed, mnemonicToSeed, seedToMnemonic } = require('./seed.js')
const Memory = require('./memory.js')

async function createUser ({ username, password }) {
  // Generate a random seed directly
  const seed = generateRandomSeed()

  // Encrypt the seed using the password and salt
  const salt = crypto.randomBytes(64)
  const encryptedSeed = encryptSeed(seed, password, salt)

  // Store the encrypted seed and salt securely with the username as the identifier
  await storeEncryptedSeedAndSalt(username, encryptedSeed, salt)

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

  // Generate a new salt
  const salt = crypto.randomBytes(64)

  // Encrypt the seed using the password and salt
  const encryptedSeed = encryptSeed(seed, password, salt)

  // Store the encrypted seed and salt securely with the username as the identifier
  await storeEncryptedSeedAndSalt(username, encryptedSeed, salt)

  // Generate the key pair from the seed
  const keyPair = generateKeyPairFromSeed(seed)

  Memory.initialize({ username, keyPair, seed })

  return keyPair
}

async function authUser ({ username, password }) {
  try {
    // Retrieve the encrypted seed and salt for the username
    const { iv, authTag, encryptedSeed, salt } = await retrieveEncryptedSeedAndSalt(username)
    if (!encryptedSeed || !salt) {
      throw new Error('Username not found or missing data.')
    }

    // Decrypt the seed using the password and salt
    const seed = decryptSeed(iv, encryptedSeed, authTag, password, salt)

    // Generate the key pair from the seed
    const keyPair = generateKeyPairFromSeed(seed)

    Memory.initialize({ username, keyPair, seed })

    // If keyPair is successfully generated, the user is authenticated
    return { username, keyPair, seed }
  } catch (error) {
    return null
  }
}

module.exports = {
  createUser,
  restoreUser,
  authUser
}
