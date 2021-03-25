/*
 Copyright 2016, 2018 IBM All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0

*/

'use strict';

const Key = require('../../Key');
const HashPrimitives = require('../../HashPrimitives');
const ECKey = require('./ec-key');
const { Certificate } = require('@fidm/x509');

// Utilitly method to make sure the start and end markers are correct
function makeRealPem(pem) {
	let result = null;
	if (typeof pem === 'string') {
		result = pem.replace(/-----BEGIN -----/, '-----BEGIN CERTIFICATE-----');
		result = result.replace(/-----END -----/, '-----END CERTIFICATE-----');
		result = result.replace(/-----([^-]+) ECDSA ([^-]+)-----([^-]*)-----([^-]+) ECDSA ([^-]+)-----/, '-----$1 EC $2-----$3-----$4 EC $5-----');
	}
	return result;
}


/**
 * This module implements the {@link module:api.Key} interface, for SM2.
 * @class SM2Key
 * @extends module:api.Key
 */
class SM2Key extends Key {
    /**
     * 
     * @param {*} key pem string of key
     */
	constructor(pem) {
		super();

        let pemString = Buffer.from(pem).toString();
        pemString = makeRealPem(pemString);

		if (pemString.includes('CERTIFICATE')) {
			const cert = Certificate.fromPEM(Buffer.from(pemString));
            this._pem = cert.publicKeyRaw.toString('base64');
			this._key = new ECKey(`-----BEGIN PUBLIC KEY-----${this._pem}-----END PUBLIC KEY-----`, 'pem');
		} else {
            this._key = new ECKey(pemString, 'pem');
            this._pem = pem.replace(/-----.*-----/g, '').replace(/(\r\n|\n|\r)/gm, '');
		}
	}

	/**
	 * @returns {string} a string representation of the hash from a sequence based on the private key bytes
	 */
	getSKI() {
        const buf = this.key.toBuffer('spki')
		// always use SHA256 regardless of the key size in effect
		return HashPrimitives.SHA2_256(buf);
	}

	/**
	 * Not supported by non PKCS11 keys.
	 * Only PKCS11 keys have a handle used by the HSM internally to access the key.
	 *
	 * @throws Error
	 */
	getHandle() {
		throw new Error('This key does not have a PKCS11 handle');
	}

	isSymmetric() {
		return false;
	}

	isPrivate() {
        return this._key.isPrivateECKey;
	}

	getPublicKey() {
		if (this.isPrivate()) {
			return new SM2Key(this._key.asPublicKey().toString('pem'));
		} 
        
        return this;
	}

	/**
	 * Generates a CSR/PKCS#10 certificate signing request for this key
	 * @param {string} subjectDN The X500Name for the certificate request in LDAP(RFC 2253) format
	 * @param {Object[]} [extensions] Additional X.509v3 extensions for the certificate signing request
	 * @returns {string} PEM-encoded PKCS#10 certificate signing request
	 * @throws Will throw an error if this is not a private key
	 * @throws Will throw an error if CSR generation fails for any other reason
	 */
	generateCSR(subjectDN, extensions) {
		throw new Error('SM2Key::generateCSR() Not implemented!');
	}

	/**
	 * Generates a self-signed X.509 certificate
	 * @param {string} [commonName] The common name to use as the subject for the X509 certificate
	 * @returns {string} PEM-encoded X.509 certificate
	 * @throws Will throw an error if this is not a private key
	 * @throws Will throw an error if X.509 certificate generation fails for any other reason
	 */
	generateX509Certificate(commonName) {
		throw new Error('SM2Key::generateX509Certificate() Not implemented!');
	}

	toBytes() {
        return this._key.toBuffer('pem');
	}
}

module.exports = SM2Key;
