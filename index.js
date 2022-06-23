var express = require('express');
var app = express();
var fs = require('fs');
var http = require('http')
var figlet = require('figlet');
var log = require('./log');
const forge = require('node-forge');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');

app.post('/key', async (req, res) => {
    // Need response to be wrapped in `<ckc>text</ckc>` as per apple fairplay requirements
    // res.setHeader("Content-Type", "text/*");

    const KSM = {
        pub: readPublicCert(),
        pri: readPrivateKey(),
        // rck: RandomContentKey(),
        ask: ReadAsk()
    }

    var playback;


    if (req.query.spc.indexOf('-') > -1 || req.query.spc.indexOf('_') > -1) {
        console.log('url encoded')
    } else if (req.query.spc.indexOf(' ') > -1 || req.query.spc.indexOf('/') > -1) {
        var buffer = Buffer.from(req.query.spc, 'base64');
        var bufString = buffer.toString('hex')
        var newB = Buffer.from(bufString, 'hex');

        console.log(newB)
        playback = newB
    } else {
        console.log('STD Method')
    }

    GenCKC(playback)
});

app.get('/', async (req, res) => {
    res.set({ 'content-type': 'text/plain; charset=utf-8' });
    res.status(200).send("OK")
})

function GenCKC(playback) {
    var spcv1 = ParseSPCV1(playback, readPublicCert(), readPrivateKey())
}

function ParseSPCV1(playback, pub, priv) {
    var spcContainer = parseSPCContainer(playback);
    var spck = decryptSPCK(pub, priv, spcContainer.EncryptedAesKey);
    console.log(spck)
    printDebugSPC(spcContainer);
}

function parseSPCContainer(playback) {
    var pb = new Buffer(playback);
    console.log(pb)
    console.log(playback.slice(0, 4))
    var spcVersion = playback.slice(0, 4)
    var spcReserved = playback.slice(4, 8)
    var AesKeyIV = playback.slice(8, 24)
    var encryptedAESKey = playback.slice(24, 152)
    var certHash = playback.slice(152, 172)
    var SPCPayloadLength = playback.slice(172, 176)
    var SPCPayload = playback.slice(176, 176 + parseInt(SPCPayloadLength.toString('hex'), 16))

    var spcContainer = {
        Version: spcVersion,
        Reserved: spcReserved,
        AesKeyIV: AesKeyIV,
        EncryptedAesKey: encryptedAESKey,
        CertificateHash:  certHash,
        SPCPayloadLength: SPCPayloadLength,
        SPCPayload: SPCPayload
    }
    console.log(spcContainer)
    return spcContainer
}

function decryptSPCK(pub, pri, enSpck) {
    if (enSpck.length !== 128) {
        console.log("Wrong [SPCK] length, must be 128")
        return null;
    }

    // TODO: Need to decrypt the SPCK using private Der certificate.
    // The DER is derived from the private key.

    // var privateDer = fs.readFileSync('ssl/private.der');
    // const decryptedData = crypto.privateDecrypt(privateDer, enSpck)

    // console.log('SPCK DATA:::')
    // console.log(decryptedData)
    
    // ! Using the spc provided in the readme, it should return: dd7139eafaceed7cda9f25da8aa915ea
}

function printDebugSPC(spcContainer) {
    const hexToUtf = convert('hex', 'ascii')
    console.log("========================= Begin SPC Data ===============================");
    console.log("SPC Container size: " + parseInt(spcContainer.SPCPayloadLength.toString('hex'), 16));
    console.log("SPC Version: " + parseInt(spcContainer.Version.toString('hex'), 16));
    console.log('Reserved: ' + spcContainer.Reserved.toString('hex'));
    console.log('CertificateHash: ' + spcContainer.CertificateHash.toString('hex'))
    console.log("SPC Encryption Key - ");
    console.log(spcContainer.EncryptedAesKey.toString('hex'));
    console.log("SPC Encryption IV - ");
    console.log(spcContainer.AesKeyIV.toString('hex'));
    console.log("SPC Payload -")
    console.log(spcContainer.SPCPayload.toString('hex'))
}

function readPublicCert() {
    var publickey = fs.readFileSync('ssl/certificate.pem');
    if (!publickey) {
        console.log('no public key')
    }
    var pubCert = parsePublicCertificate(publickey);
    return pubCert;
}

function readPrivateKey() {
    var privatekey = fs.readFileSync('ssl/dev_private_key.pem');
    if (!privatekey) {
        console.log('no private key');
    }
    var priKey = decryptPrivateKey(privatekey, Int8Array.from(' '));
    return priKey;
}

const convert = (from, to) => str => Buffer.from(str, from).toString(to)

function ReadAsk() {
    var askkey = "d87ce7a26081de2e8eb8acef3a6dc179";
    var hex = askkey.toString();
    const hexToUtf = convert('hex', 'ascii')
    return hexToUtf(askkey);
}

function parsePublicCertificate(pbkey) {
    const cert = forge.pki.certificateFromPem(pbkey);
    return cert;
}

function decryptPrivateKey(pvkey, passphrase) {
    var privatekey = fs.readFileSync('ssl/privatekey.der');
    return privatekey;    
}

const PORT = 8080;
var httpsServer = http.createServer(app);
var server = httpsServer.listen(PORT);

console.log('\033[2J');
figlet('FAIRPLAY     KSM', function(err, data) {
    if (err) {
      console.log('An error has occurred:' + err);
      return;
    }
    console.log(data)
    log.info(`Server Running on ${PORT} / http://localhost:${PORT}`)
});