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
const { createUser, authUser, restoreUser } = require('./src/utils/users.js')

module.exports = {
  Memory,
  authCLI,
  createUser,
  authUser,
  restoreUser,
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
  getConfig,
  setConfig,
  loadConfigs
}
