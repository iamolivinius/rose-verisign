#!/usr/bin/env node

var chalk = require('chalk');
var crypto = require('crypto');
var fs = require('fs');
var path = require('path');
var esprima = require('esprima');
var escodegen = require('escodegen');

var argv = require('yargs')
            .usage('Usage: $0 <command> [options]')

            .command('sign', 'sign the given JSON file')
            .example('$0 sign -f foo.json -k private.key', 'sign a given file with a private key')

            .command('verify', 'verify the given JSON file')
            .example('$0 verify -f foo.json -k public.key', 'verify a given file with a public key')

            .demand(1)

            .demand('f')
            .alias('f', 'file')
            .describe('f', 'Load a JSON file')
            .nargs('f', 1)

            .demand('k')
            .alias('k', 'key')
            .describe('k', 'Load a private/public key from file')
            .nargs('k', 1)

            .alias('i', 'inline')
            .describe('i', 'Inlines the signature into the original JSON object')

            .help('h')
            .alias('h', 'help')
            .epilog('copyright 2015')

            .argv;

var ALGORITHM = 'RSA-SHA256';

var command = argv._[0];

// read JSON file and key file
var jsonFile = fs.readFileSync(path.normalize(argv.f), { encoding: 'utf8' });
var keyFile = fs.readFileSync(path.normalize(argv.k), { encoding: 'utf8' });

// check if file content is valid JSON
var jsonObject = JSON.parse(jsonFile);

// validate 'process' function and remove unnecessary whitespaces before
// signing
jsonObject.patterns.forEach(function(pattern) {
  if (typeof pattern.process === 'string') {
    var ast = esprima.parse(pattern.process);
    pattern.process = escodegen.generate(ast, {
      format: {
        compact: true
      }
    });
  }
});

// create valid string from JSON object
var validatedJSON = JSON.stringify(jsonObject);

if (command === 'sign') {
  // create signing object
  // https://iojs.org/api/crypto.html#crypto_crypto_createsign_algorithm
  var sign = crypto.createSign(ALGORITHM);
  sign.update(validatedJSON);

  // create signature in hex format
  var signature = sign.sign(keyFile, 'hex');

  if (argv.i) {
    jsonObject.signature = signature;
    console.log(JSON.stringify(jsonObject, null, 2));
  } else {
    console.log(signature);
  }
}

if (command === 'verify') {
  if (!jsonObject.signature) {
    console.log(chalk.blue('Can not verify file. No signature included'));
    process.exit(1);
  }

  var signature = jsonObject.signature;
  delete jsonObject.signature;

  validatedJSON = JSON.stringify(jsonObject);

  var verify = crypto.createVerify(ALGORITHM);
  verify.update(validatedJSON);
  var valid = verify.verify(keyFile, signature, 'hex');

  if (valid) {
    console.log(chalk.green('Congratulations, verification successfull!'));
    process.exit(0);
  } else {
    console.log(chalk.red('Error, verification failed!'));
    process.exit(1);
  }
}
