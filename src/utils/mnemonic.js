const { generateKeyPairFromSeed } = require('./seed')
const sodium = require('sodium-universal')
const wordlist = require('./wordlist.json')
const INVALID_MNEMONIC = 'Invalid mnemonic'
const INVALID_ENTROPY = 'Invalid entropy'
const INVALID_CHECKSUM = 'Invalid mnemonic checksum'

function lpad (str, padString, length) {
  while (str.length < length) {
    str = padString + str
  }
  return str
}

function bytesToBinary (bytes) {
  return bytes.map((byte) => byte.toString(2).padStart(8, '0')).join('')
}

function deriveChecksumBits (entropy) {
  const ENT = entropy.length * 8
  const CS = ENT / 32

  const hash = Buffer.alloc(sodium.crypto_hash_sha256_BYTES)
  sodium.crypto_hash_sha256(hash, entropy)

  const bits = bytesToBinary(Array.from(hash))
  return bits.slice(0, CS)
}

function binaryToByte (binary) {
  return parseInt(binary, 2)
}

function normalize (str) {
  return (str || '').normalize('NFKD')
}

function entropyToMnemonic (entropy) {
  if (!Buffer.isBuffer(entropy)) {
    entropy = Buffer.from(entropy, 'hex')
  }

  // 128 <= ENT <= 256
  if (entropy.length < 16) {
    throw new TypeError(INVALID_ENTROPY)
  }
  if (entropy.length > 32) {
    throw new TypeError(INVALID_ENTROPY)
  }
  if (entropy.length % 4 !== 0) {
    throw new TypeError(INVALID_ENTROPY)
  }

  const entropyBits = bytesToBinary(Array.from(entropy))
  const checksumBits = deriveChecksumBits(entropy)
  const bits = entropyBits + checksumBits
  const chunks = bits.match(/(.{1,11})/g)
  const words = chunks.map((binary) => {
    const index = binaryToByte(binary)
    return wordlist[index]
  })

  return words.join(' ')
}

function mnemonicToEntropy (mnemonic) {
  const words = normalize(mnemonic).split(' ')
  if (words.length % 3 !== 0) {
    throw new Error(INVALID_MNEMONIC)
  }
  // convert word indices to 11 bit binary strings
  const bits = words
    .map((word) => {
      const index = wordlist.indexOf(word)
      if (index === -1) {
        throw new Error(INVALID_MNEMONIC)
      }
      return lpad(index.toString(2), '0', 11)
    })
    .join('')
  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32
  const entropyBits = bits.slice(0, dividerIndex)
  const checksumBits = bits.slice(dividerIndex)
  // calculate the checksum and compare
  const entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte)
  if (entropyBytes.length < 16) {
    throw new Error(INVALID_ENTROPY)
  }
  if (entropyBytes.length > 32) {
    throw new Error(INVALID_ENTROPY)
  }
  if (entropyBytes.length % 4 !== 0) {
    throw new Error(INVALID_ENTROPY)
  }
  const entropy = Buffer.from(entropyBytes)
  const newChecksum = deriveChecksumBits(entropy)
  if (newChecksum !== checksumBits) {
    throw new Error(INVALID_CHECKSUM)
  }
  return entropy.toString('hex')
}

function mnemonicToSeed (mnemonic, password) {
  const mnemonicBuffer = Buffer.from(normalize(mnemonic), 'utf8')
  const salt = 'mnemonic' + (password ? normalize(password) : '')
  const saltBuffer = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES)
  Buffer.from(salt, 'utf8').copy(saltBuffer)
  const key = Buffer.alloc(sodium.randombytes_SEEDBYTES)

  sodium.crypto_pwhash(
    key,
    mnemonicBuffer,
    saltBuffer,
    Number(process.env.OPSLIMIT || sodium.crypto_pwhash_OPSLIMIT_SENSITIVE),
    Number(process.env.MEMLIMIT || sodium.crypto_pwhash_MEMLIMIT_SENSITIVE),
    sodium.crypto_pwhash_ALG_DEFAULT
  )

  return key
}

function validateMnemonic (mnemonic) {
  try {
    mnemonicToEntropy(mnemonic, wordlist)
  } catch (e) {
    return false
  }
  return true
}

function validateSeed (s) {
  const seed = typeof s === 'string' ? s : s.toString('hex')
  const hexRegex = /^[0-9a-fA-F]{64}$/
  return seed.length === 64 && hexRegex.test(seed)
}

function generateKeyPairFromMnemonic (mnemonic) {
  if (!validateMnemonic(mnemonic)) throw new Error('Invalid mnemonic')
  const seed = mnemonicToSeed(mnemonic)
  return generateKeyPairFromSeed(seed)
}

module.exports = {
  validateSeed,
  generateKeyPairFromMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  entropyToMnemonic
}
