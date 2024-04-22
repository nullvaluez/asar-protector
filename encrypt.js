const fs = require('fs');
const ffi = require('ffi-napi');
const path = require('path');
const crypto = require('crypto');

// generate random 16-byte iv
const iv = crypto.randomBytes(16);

let hasPrefix = false;

const cipher = crypto.createCipheriv('aes-256-cbc', 'password', iv);
cipher.setAutoPadding(true);
cipher.setEncoding('base64');

// monkey patch push method to inject the IV at the beginning
const _p = cipher.push;
cipher.push = function (chunk, enc) {
    if (!hasPrefix && chunk !== null) {
        return _p.call(this, Buffer.concat([iv, chunk]), enc);
    } else {
      return _p.call(this, chunk, enc);
    }
}
  return cipher;


