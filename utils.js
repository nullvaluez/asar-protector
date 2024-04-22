function getPlatform() {
    if (process.platform === 'win32') {
        return 'windows';
    } else if (process.platform === 'darwin') {
        return 'mac';
    } else {
        return 'linux';
    }
}

module.exports = { getPlatform };