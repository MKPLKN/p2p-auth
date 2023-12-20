#!/usr/bin/env node
const { program } = require('commander')
const authCLI = require('./src/commands/auth.js')

program
  .command('auth')
  .description('Handle authentication')
  .action(authCLI)

program.parse(process.argv)
