var express = require('express');
var app = express();
var fs = require('fs');
var http = require('http')
var figlet = require('figlet');
var log = require('./log');
const forge = require('node-forge');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');
const CryptoJS = require('crypto-js');
var pkcs7 = require('pkcs7-padding');

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
    // console.log(spck)
    // printDebugSPC(spcContainer);
    spcPayload = AESCBCDecrypt(spck, spcContainer.AesKeyIV, spcContainer.SPCPayload)
    var ttlvs = parseTTLVs(spcPayload);

    // console.log('=== SPC PayloadRow ===');
    // console.log(spcPayload)
    // console.log(spcContainer)

}

function parseTTLVs(spcPayload) {
}

function AESCBCDecrypt(key, iv, text) {
    // const { algorithm, mode, padding, createDecryptStream } = require('cryptian')

    var encInfo = [
        {
            key: key.toString('hex'),
            keyLength: key.toString('hex').length,
            kl: key.length,
            k: key,
            iv: iv.toString('hex'),
            ivLength: iv.toString('hex').length,
            ivl: iv.length,
            i: iv
        }
    ]
    console.table(encInfo);

    // var nkey = key.toString('base64');
    // var niv = iv.toString('base64');
    // var ntext = text.toString('base64');
    // const des = new algorithm.Des();
    // des.setKey(nkey);

    // const padder = new padding.Pkcs5(8);
    // const cipher = new mode.cbc.Decipher(des, niv);
    // console.log(cipher.transform(ntext).toString('hex'));

    // const contents = Buffer.from(text, 'hex');
    // const wiv = niv.slice(0, 16);
    // // const textBytes = contents.slice(BLOCK_SIZE);

    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    decipher.setAutoPadding(false);
    let decrypted = decipher.update(text, 'hex', 'hex');
    decrypted += decipher.final('hex');
    return decrypted;
    // console.log(decrypted)
    // console.log(decrypted.length)

    // if (decrypted.length % 128 != 0) {
    //     console.log('ciphertext is not a multiple of the block size')
    // }


    // console.log(padder.unpad(Buffer.from(cipher.transform(ntext)), 'hex').toString('hex'));

    // var ntext = Buffer.from(text).toString('hex');
    // var nkey = Buffer.from(key, 'hex');
    // let padded = pkcs7.unpad(text);

    // let cipher = crypto.createDecipheriv('aes-256-cbc', key, iv.toString('hex').slice(0, 16));
    // cipher.update(padded, 'hex');
    // cipher.setAutoPadding(false);
    // let ivCiphertext = Buffer.concat([iv, cipher.update(padded), cipher.final()]);

    // console.log(ivCiphertext.toString('hex'))
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
    // console.log(spcContainer)
    return spcContainer
}

function decryptSPCK(pub, pri, enSpck) {
    if (enSpck.length !== 128) {
        console.log("Wrong [SPCK] length, must be 128")
        return null;
    }

    // OAEPDecrypt
    const decryptedData = crypto.privateDecrypt({
        key: pri,
        passphrase: Int8Array.from(' '),
      },
      Buffer.from(enSpck, "base64"));
    
    return decryptedData;
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
    // var priKey = decryptPrivateKey(privatekey, Int8Array.from(' '));
    return privatekey;
}

const convert = (from, to) => str => Buffer.from(str, from).toString(to)

// function Int64ToString(bytes, isSigned) {
//     const isNegative = isSigned && bytes.length > 0 && bytes[0] >= 0x80;
//     const digits = [];
//     bytes.forEach((byte, j) => {
//       if(isNegative)
//         byte = 0x100 - (j == bytes.length - 1 ? 0 : 1) - byte;
//       for(let i = 0; byte > 0 || i < digits.length; i++) {
//         byte += (digits[i] || 0) * 0x100;
//         digits[i] = byte % 10;
//         byte = (byte - digits[i]) / 10;
//       }
//     });
//     return (isNegative ? '-' : '') + digits.reverse().join('');
// }

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

// ! REMOVE DO NOT NEED
// function decryptPrivateKey(pvkey, passphrase) {
//     var privatekey = fs.readFileSync('ssl/dev_certificate.der');
//     return privatekey;    
// }

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