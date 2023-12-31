const { generateChildKeyPair, generateMasterKeyPairFromMnemonic, mnemonicToSeed } = require('./src/utils/seed.js')

// Example usage
const mnemonic = 'quantum float volcano kiss often sniff zone lunar own civil episode party train lamp win satisfy eagle marriage slow hammer shoot chest total borrow'
const masterSeed = mnemonicToSeed(mnemonic)
const masterKeyPair = generateMasterKeyPairFromMnemonic(mnemonic)

console.log({ masterSeed })

// Derive a child seed and generate a key pair
const childKeyPair = generateChildKeyPair(masterSeed, "m/0'/1/0")

console.log('Master Key Pair:', masterKeyPair)
console.log('Child Key Pair:', childKeyPair)
