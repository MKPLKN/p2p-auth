import { authCLI } from './src/commands/auth.js'
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
import { createUser } from './src/utils/users.js'

export {
  authCLI,
  createUser,
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
