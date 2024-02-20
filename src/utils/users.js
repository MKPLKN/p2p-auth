const { storeNonceChiperAndSalt, retrieveNonceChiperAndSalt } = require('./storage.js')
const { generateKeyPairFromSeed, decryptSeed, encryptSeed } = require('./seed.js')
const { entropyToMnemonic, mnemonicToSeed } = require('./mnemonic.js')
const Memory = require('./memory.js')
const { randomBytes } = require('hypercore-crypto')
const sodium = require('sodium-universal')

async function createUser ({ username, password }) {
  const entropy = randomBytes(32)
  const mnemonic = entropyToMnemonic(entropy)
  const seed = mnemonicToSeed(mnemonic)
  const keyPair = generateKeyPairFromSeed(seed)

  const salt = randomBytes(sodium.crypto_pwhash_SALTBYTES)
  const nonceAndChiper = encryptSeed(seed, password, salt)
  await storeNonceChiperAndSalt(username, { ...nonceAndChiper, salt })

  Memory.initialize({ username, keyPair, seed })

  return { mnemonic, keyPair, seed: seed.toString('hex') }
}

async function restoreUser ({ seedPhrase, username, password }) {
  const seed = mnemonicToSeed(seedPhrase)
  const salt = randomBytes(sodium.crypto_pwhash_SALTBYTES)
  const nonceAndChiper = encryptSeed(seed, password, salt)

  await storeNonceChiperAndSalt(username, { ...nonceAndChiper, salt })
  const keyPair = generateKeyPairFromSeed(seed)

  Memory.initialize({ username, keyPair, seed })

  return keyPair
}

async function authUser ({ username, password }) {
  try {
    const { nonce, ciphertext, salt } = await retrieveNonceChiperAndSalt(username)
    if (!ciphertext || !salt) {
      throw new Error('Username not found or missing data.')
    }

    const seed = decryptSeed({ nonce, ciphertext, salt, password })
    const keyPair = generateKeyPairFromSeed(seed)

    Memory.initialize({ username, keyPair, seed })

    // If keyPair is successfully generated, the user is authenticated
    return { username, keyPair, seed }
  } catch (error) {
    return null
  }
}

async function usernameExists (username) {
  const response = await retrieveNonceChiperAndSalt(username)
  return response.code !== 404
}

module.exports = {
  usernameExists,
  createUser,
  restoreUser,
  authUser
}
