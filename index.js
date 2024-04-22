const ffi = require('ffi-napi');
const archiver = require('archiver');
const fs = require('fs');
const yargs = require('yargs');
const path = require('path');
const { execSync } = require('child_process');
const { getPlatform } = require('./utils');

// load native modules
const nativeBinding = ffi.Library('./binding', {
    encrypt: ['buffer', ['string', 'string']],
    bloat: ['buffer', ['string', 'size_t']],
    decrypt: ['buffer', ['string', 'string']],
    compress: ['buffer', ['string']],
    decompress: ['buffer', ['string']],
});

// get platform
const platform = getPlatform();
console.log(`Platform: ${platform}`);

// function to harden the asar
// function to harden the asar
async function hardenAsar(srcPath, dstPath, password, bloatSize) {
    // read the asar, provide encryption using nativeBinding.encrypt
    const asar = fs.readFileSync(srcPath);
    // create logic for bloating the asar
    // if its tampered with, bloat terabytes
    const bloat = Buffer.alloc(1024 * 1024 * 1024 * 1024);
    const bloatAsar = Buffer.concat([asar, bloat]);
    const antiTamper = nativeBinding.encrypt(bloatAsar, password);
    const encryptedAsar = nativeBinding.encrypt(asar, password);
    
    fs.writeFileSync(dstPath, antiTamper, encryptedAsar);
}

// Command-line interface using yargs
const argv = yargs
  .command('harden <src> <dst> <password>', 'Harden an ASAR file', (yargs) => {
    yargs.positional('src', { describe: 'Path to the source ASAR file' });
    yargs.positional('dst', { describe: 'Path to the destination hardened ASAR file' });
    yargs.positional('password', { describe: 'Password for encryption' });
    yargs.option('bloat-size', {
      describe: 'Bloat size in bytes (default: 1 GB)',
      type: 'number',
      default: 1024 * 1024 * 1024
    });
  })
  .help()
  .argv;

// call hardenAsar with arguments from argv
hardenAsar(argv.src, argv.dst, argv.password, argv.bloatSize)
  .then(() => console.log('ASAR hardening completed.'))
  .catch(error => console.error('Error during ASAR hardening:', error));

