// Based on https://github.com/codedot/xmm/tree/daemon

const crypto = require('crypto')
const https = require('https')
const basex = require('base-x')
const secp256k1 = require('secp256k1')

const bs58 = basex('rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz')

const privateKey = Buffer.from('e55dc8f3741ac9668dbe858409e5d64f5ce88380f7228eccfe82b92b2c7848ba', 'hex')

const sha256 = (data) => crypto.createHash('sha256').update(data).digest()
const sha512 = (data) => crypto.createHash('sha512').update(data).digest()

function checksum (buf) {
    return sha256(sha256(buf)).slice(0, 4)
}

function xor (buf1, buf2) {
    const xored = Buffer.from(buf1)
    for (let i = 0; i < buf1.length; ++i) xored[i] ^= buf2[i]
    return xored
}

function mkshared (socket) {
    const cookie1 = socket.getFinished()
    const cookie2 = socket.getPeerFinished()
    console.log(`cookie1 (${cookie1.length}): ${cookie1.toString('hex')}`)
    console.log(`cookie2 (${cookie2.length}): ${cookie2.toString('hex')}`)
    const mix = xor(sha512(cookie1), sha512(cookie2))
    return sha512(mix).slice(0, 32)
}

function sign (socket) {
    const msg = mkshared(socket)
    const { signature: sig } = secp256k1.ecdsaSign(msg, privateKey)
    return secp256k1.signatureExport(sig, Buffer.allocUnsafe).toString('base64')
}

function getSerializedPublicKey () {
    const type = Buffer.from([28])
    const pubkey = secp256k1.publicKeyCreate(privateKey, true, Buffer.allocUnsafe)
    const sum = checksum(Buffer.concat([type, pubkey]))
    const buf = Buffer.concat([type, pubkey, sum])
    return bs58.encode(buf)
}

function verify (socket, headers) {
    const assert = (value, msg) => {
        if (!value) {
            console.error(msg)
            process.exit(1)
        }
    }

    const buf = bs58.decode(headers['public-key'])
    const pubkey = buf.slice(1, 34)

    assert(buf.length === 38, 'Invalid public key buffer length')
    assert(buf[0] === 28, 'Invalid public key prefix')
    assert(buf.slice(34, 38).equals(checksum(buf.slice(0, 34))), 'Public key buffer checksum mismatch')

    const msg = mkshared(socket)
    const sig = secp256k1.signatureImport(Buffer.from(headers['session-signature'], 'base64'))
    assert(secp256k1.ecdsaVerify(sig, msg, pubkey), 'Signature verification failed')
}

;(async () => {
    const req = https.request({
        host: 'r.ripple.com',
        port: 51235,
        headers: {
            Upgrade: 'XRPL/2.0',
            Connection: 'Upgrade',
            'Connect-As': 'Peer',
            'Network-ID': 0,
        },
        rejectUnauthorized: false,
    })

    req.on('response', (res) => {
        console.log('on response')
        console.log(`STATUS: ${res.statusCode}`);
        console.log(`HEADERS: ${JSON.stringify(res.headers, null, 2)}`);
        res.setEncoding('utf8')

        const chunks = []
        res.on('data', (data) => chunks.push(data))
        res.on('end', () => {
            console.log(`BODY: ${chunks.join('')}`)
        })
    })

    req.on('error', (err) => {
        console.log('on error')
        console.error(err)
    })

    req.on('socket', (socket) => {
        console.log('on socket')
        socket.on('secureConnect', () => {
            console.log('on secureConnect')
            req.setHeader('Public-Key', getSerializedPublicKey())
            req.setHeader('Session-Signature', sign(socket))
            req.end()
        })
    })

    req.on('upgrade', (res, socket, data) => {
        console.log('on upgrade')
        console.log(`STATUS: ${res.statusCode}`);
        console.log(`HEADERS: ${JSON.stringify(res.headers, null, 2)}`);
        console.log(`DATA: ${data.toString('utf8')}`)

        verify(socket, res.headers)

        socket.on('data', (d) => console.log(d))
    })
})().catch((err) => {
    console.error(err)
    process.exit(1)
})
