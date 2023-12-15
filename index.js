import { authCLI } from './src/commands/auth.js'
import { Memory } from './src/utils/memory.js'
import {
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
} from './src/utils/seed.js'
import { createUser, authUser, restoreUser } from './src/utils/users.js'

export {
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
  encryptSeed
}
