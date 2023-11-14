import { userActionPrompt, authUserPrompt, createUserQuestions, restoreUserQuestions } from '../utils/prompts.js'
import { authUser, createUser, restoreUser } from '../utils/users.js'

async function handleLogin () {
  const { username, password } = await authUserPrompt()

  // Fallback, if no users are created
  if (!username || !password) {
    const { username, password } = await createUserQuestions()
    const { mnemonic, keyPair, seed } = await createUser({ username, password })

    console.log('New user created!', { username, mnemonic, publicKey: keyPair.publicKey.toString('hex') })
    return { username, keyPair, seed }
  }

  const { keyPair, seed } = await authUser({ username, password })
  if (keyPair && keyPair.publicKey) {
    console.log('User authenticated!', { publicKey: keyPair.publicKey.toString('hex') })
  } else {
    console.error('Authentication failed!')
  }

  return { username, keyPair, seed }
}

async function handleCreateUser () {
  const { username, password } = await createUserQuestions()
  const { mnemonic, keyPair, seed } = await createUser({ username, password })

  console.log('New user created!', { username, mnemonic, publicKey: keyPair.publicKey.toString('hex') })

  return { username, keyPair, seed }
}

async function handleRestoreUser () {
  const { seedPhrase, username, password } = await restoreUserQuestions()
  console.log('New user created!', { username })

  const keyPair = await restoreUser({ seedPhrase, username, password })
  console.log('User authenticated!', { publicKey: keyPair.publicKey.toString('hex') })
}

export async function authCLI () {
  const { action } = await userActionPrompt()

  switch (action) {
    case 'Log in':
      return await handleLogin()

    case 'Create User':
      return await handleCreateUser()

    case 'Restore User':
      return await handleRestoreUser()

    default:
      break
  }
}
