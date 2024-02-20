const inquirer = require('inquirer')
const { getUsersList } = require('./storage.js')
const { validateMnemonic } = require('./mnemonic.js')

function userActionPrompt () {
  return inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'What do you want to do?',
      choices: ['Log in', 'Create User', 'Restore User']
    }
  ])
}

async function authUserPrompt () {
  const users = await getUsersList()

  if (users.length === 0) {
    console.log('No user accounts found.')
    return { code: 404 }
  }

  const { username } = await inquirer.prompt([
    {
      type: 'list',
      name: 'username',
      message: 'Choose an account to log in:',
      choices: users
    }
  ])

  const { password } = await inquirer.prompt([
    {
      type: 'password',
      name: 'password',
      message: 'Enter password:',
      mask: '*',
      validate: async (input) => {
        if (input.trim() === '') {
          return 'Password cannot be empty'
        }
        return true
      }
    }
  ])

  return { username, password }
}

async function createUserQuestions () {
  // Ask for username and password (with confirmation)
  let username, password, confirmPassword
  let isPasswordMatch = false

  while (!isPasswordMatch) {
    ({ username, password, confirmPassword } = await inquirer.prompt([
      {
        type: 'input',
        name: 'username',
        message: 'Enter a username for this keypair (used locally for identification):'
      },
      {
        type: 'password',
        name: 'password',
        message: 'Set a password for easier future access (used locally):',
        mask: '*',
        validate: async (input) => {
          if (input.trim() === '') {
            return 'Password cannot be empty'
          }
          return true
        }
      },
      {
        type: 'password',
        name: 'confirmPassword',
        message: 'Confirm your password:',
        mask: '*'
      }
    ]))

    if (password !== confirmPassword) {
      console.error('Passwords do not match. Please try again.')
    } else {
      isPasswordMatch = true
    }
  }

  return { username, password }
}

async function restoreUserQuestions () {
  let seedPhrase
  let isValidSeed = false

  // First, prompt for and validate the seed phrase
  while (!isValidSeed) {
    ({ seedPhrase } = await inquirer.prompt([
      {
        type: 'input',
        name: 'seedPhrase',
        message: 'Enter your seed phrase to restore your key pair:'
      }
    ]))

    isValidSeed = validateMnemonic(seedPhrase)
    if (!isValidSeed) {
      console.error('Invalid seed phrase. Please try again.')
    }
  }

  // Ask for username and password (with confirmation)
  let username, password, confirmPassword
  let isPasswordMatch = false

  while (!isPasswordMatch) {
    ({ username, password, confirmPassword } = await inquirer.prompt([
      {
        type: 'input',
        name: 'username',
        message: 'Enter a username for this keypair (used locally for identification):'
      },
      {
        type: 'password',
        name: 'password',
        message: 'Set a password for easier future access (used locally):',
        mask: '*',
        validate: async (input) => {
          if (input.trim() === '') {
            return 'Password cannot be empty'
          }
          return true
        }
      },
      {
        type: 'password',
        name: 'confirmPassword',
        message: 'Confirm your password:',
        mask: '*'
      }
    ]))

    if (password !== confirmPassword) {
      console.error('Passwords do not match. Please try again.')
    } else {
      isPasswordMatch = true
    }
  }

  return { seedPhrase, username, password }
}

module.exports = {
  userActionPrompt,
  authUserPrompt,
  createUserQuestions,
  restoreUserQuestions
}
