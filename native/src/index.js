const { Napi:: Env, Napi:: Object, Napi:: Function, Napi:: String, Napi:: Buffer } = require('node-addon-api');
const { encryptData, bloatData, calculateChecksum } = require('./binding');

// Wrapper function for encryptData
function encrypt(data, password) {
    const buffer = Buffer.from(data);
    const resultBuffer = encryptData(buffer, password);
    return resultBuffer.toString('base64'); // Return as base64 encoded string
}

// Wrapper function for bloatData
function bloat(data, bloatSize) {
    const buffer = Buffer.from(data, 'base64'); // Decode base64
    const resultBuffer = bloatData(buffer, bloatSize);
    return resultBuffer.toString('base64'); // Return as base64 encoded string
}

// Wrapper function for calculateChecksum
function checksum(data) {
    const buffer = Buffer.from(data, 'base64'); // Decode base64
    return calculateChecksum(buffer);
}

// Initialize native module and export functions
const initialize = (env, exports) => {
    exports.encrypt = Function:: New(env, encrypt);
    exports.bloat = Function:: New(env, bloat);
    exports.checksum = Function:: New(env, checksum);
    return exports;
};

module.exports = initialize;