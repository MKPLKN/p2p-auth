module.exports = class Memory {
  constructor () {
    this.seed = null
    this.keyPair = null
    this.username = null
  }

  static initialize ({ seed, keyPair, username }) {
    this.seed = seed
    this.keyPair = {
      ...keyPair,
      publicKeyHex: keyPair.publicKey.toString('hex'),
      pubkey: keyPair.publicKey.toString('hex')
    }
    this.username = username
  }

  static setSeed (seed) {
    this.seed = seed
  }

  static getSeed () {
    if (!this.seed) {
      throw new Error('Seed is not initialized')
    }
    return this.seed
  }

  static setUsername (user) {
    this.username = user
  }

  static hasUsername () {
    return !!this.username
  }

  static getUsername () {
    if (!this.username) {
      throw new Error('Username is not initialized')
    }
    return this.username
  }

  static setKeyPair (keyPair) {
    this.keyPair = {
      ...keyPair,
      publicKeyHex: keyPair.publicKey.toString('hex'),
      pubkey: keyPair.publicKey.toString('hex')
    }
  }

  static getKeyPair (key = null) {
    if (!this.keyPair) {
      throw new Error('KeyPair is not initialized')
    }

    return key ? this.keyPair[key] ?? null : this.keyPair
  }
}
