const authCLI = require('./src/commands/auth.js')
const { getConfig, setConfig, loadConfigs } = require('./src/utils/config.js')
const Memory = require('./src/utils/memory.js')
const {
  getDerivationPath,
  getNextDerivedPath,
  increaseDerivationPath,
  generateChildKeyPair,
  generateKeyPairFromSeed,
  generateMasterKeyPairFromMnemonic,
  generateEncryptionKeyFromKeyPair,
  deriveChildSeed,
  generateRandomSeed,
  seedToMnemonic,
  mnemonicToSeed,
  validateSeedPhrase,
  decryptSeed,
  encryptSeed
} = require('./src/utils/seed.js')
const { createUser, authUser, restoreUser, usernameExists } = require('./src/utils/users.js')

module.exports = {
  Memory,
  authCLI,

  // users.js
  createUser,
  authUser,
  restoreUser,
  usernameExists,

  // seed.js
  getDerivationPath,
  getNextDerivedPath,
  increaseDerivationPath,
  generateChildKeyPair,
  generateKeyPairFromSeed,
  generateMasterKeyPairFromMnemonic,
  generateEncryptionKeyFromKeyPair,
  deriveChildSeed,
  generateRandomSeed,
  seedToMnemonic,
  mnemonicToSeed,
  validateSeedPhrase,
  decryptSeed,
  encryptSeed,

  // config.js
  getConfig,
  setConfig,
  loadConfigs
}
