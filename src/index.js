const ffi = require('ffi-napi');
const archiver = require('archiver');
const fs = require('fs');
const crypto = require('crypto');
const yargs = require('yargs');

// Load native module
const nativeBinding = ffi.Library('./native/binding', {
    encrypt: ['string', ['string', 'string']],
    bloat: ['string', ['string', 'size_t']],
    checksum: ['string', ['string']]
});

async function hardenAsar(srcPath, dstPath, password, bloatSize, stealthMode = false, honeytoken) {
    try {
        // 1. Read ASAR contents
        const asarData = await fs.promises.readFile(srcPath);

        // 2. Calculate checksum for original ASAR
        const originalChecksum = nativeBinding.checksum(asarData.toString('base64'));

        // 3. Encrypt data using native module
        const encryptedData = nativeBinding.encrypt(asarData.toString('base64'), password);

        // 4. Bloating
        const bloatedData = nativeBinding.bloat(encryptedData, bloatSize);

        // 5. Honeytoken (embed if provided)
        if (honeytoken) {
            // ... (Append honeytoken data to bloatedData)
        }

        // 6. Anti-tampering: Embed checksum
        const protectedData = Buffer.concat([
            Buffer.from(originalChecksum, 'hex'),
            Buffer.from(bloatedData, 'base64')
        ]);

        // 7. Create new ASAR archive
        const archive = archiver('asar');
        archive.append(protectedData, { name: 'app.asar' }); // Use original filename
        await archive.finalize();

        // 8. Write the hardened ASAR to dstPath
        await fs.promises.writeFile(dstPath, archive);

        console.log('ASAR hardened successfully!');
    } catch (error) {
        console.error('Error hardening ASAR:', error);
        throw error;
    }
}

// cli options
yargs.command({
    command: 'harden',
    describe: 'Harden an ASAR archive',
    builder: {
        src: {
            describe: 'Source ASAR archive path',
            demandOption: true,
            type: 'string'
        },
        dst: {
            describe: 'Destination path for hardened ASAR archive',
            demandOption: true,
            type: 'string'
        },
        password: {
            describe: 'Password for encryption',
            demandOption: true,
            type: 'string'
        },
        bloatSize: {
            describe: 'Size of bloat data (in bytes)',
            demandOption: true,
            type: 'number'
        },
        stealth: {
            describe: 'Enable stealth mode',
            type: 'boolean'
        },
        honeytoken: {
            describe: 'Embed honeytoken data',
            type: 'string'
        }
    },
    handler: (argv) => {
        hardenAsar(argv.src, argv.dst, argv.password, argv.bloatSize, argv.stealth, argv.honeytoken);
    }
}).argv;