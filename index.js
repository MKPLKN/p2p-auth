const authCLI = require('./src/commands/auth.js')
const Memory = require('./src/utils/memory.js')
const { createUser, authUser, restoreUser, usernameExists } = require('./src/utils/users.js')
const { generateKeyPairFromMnemonic, mnemonicToSeed, entropyToMnemonic } = require('./src/utils/mnemonic.js')
const { generateChildKeyPair, generateKeyPairFromSeed, generateEncryptionKeyFromKeyPair, decryptSeed, encryptSeed, getKeyChain } = require('./src/utils/seed.js')
const { getConfig, setConfig, loadConfigs } = require('./src/utils/config.js')

module.exports = {
  Memory,
  authCLI,

  // users.js
  createUser,
  authUser,
  restoreUser,
  usernameExists,

  // mnemonic.js
  generateKeyPairFromMnemonic,
  mnemonicToSeed,
  entropyToMnemonic,

  // seed.js
  getKeyChain,
  generateChildKeyPair,
  generateKeyPairFromSeed,
  generateEncryptionKeyFromKeyPair,
  decryptSeed,
  encryptSeed,

  // config.js
  getConfig,
  setConfig,
  loadConfigs
}
