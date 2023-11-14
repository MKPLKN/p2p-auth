#!/usr/bin/env node
import { program } from 'commander'
import { authCLI } from './src/commands/auth.js'

program
  .command('auth')
  .description('Handle authentication')
  .action(authCLI)

program.parse(process.argv)
