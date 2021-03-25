/*
 Copyright 2021 Runchain Fintech All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0

*/

'use strict';

// requires
const { CryptoSuite, Utils: utils} = require('../../');
const SM2Key = require('./sm2/key');
const { Signer } = require('./signer.node');

const logger = utils.getLogger('crypto_sm2_sm4');

/**
 * The {@link module:api.CryptoSuite} implementation for ECDSA, and AES algorithms using software key generation.
 * This class implements a software-based key generation (as opposed to Hardware Security Module based key management)
 *
 * @class
 * @extends module:api.CryptoSuite
 */
class CryptoSuite_SM2_SM4 extends CryptoSuite {

	/**
	 * constructor
	 *
	 * @param {number} keySize Key size for the ECDSA algorithm, can only be 256 or 384
	 * @param {string} hash Optional. Hash algorithm, supported values are "SHA2" and "SHA3"
	 */
	constructor() {
		super();
		this._cryptoKeyStore = null;
		this._curveName = `sm2`;
		logger.debug('Hash algorithm: SM3, hash output size: 256');
	}

	/**
	 * Set the cryptoKeyStore.
	 *
	 * When the application needs to use a key store other than the default,
	 * it should use the {@link Client} newCryptoKeyStore to create an instance and
	 * use this function to set the instance on the CryptoSuite.
	 *
	 * @param {CryptoKeyStore} cryptoKeyStore The cryptoKeyStore.
	 */
	setCryptoKeyStore(cryptoKeyStore) {
		this._cryptoKeyStore = cryptoKeyStore;
	}

	/**
	 * This is an implementation of {@link module:api.CryptoSuite#deriveKey}
	 * To be implemented
	 */
	deriveKey(key, opts) {
		throw new Error('CryptoSuite_SM2_SM4::deriveKey() Not implemented yet');
	}

	/**
	 * This is an implementation of {@link module:api.CryptoSuite#createKeyFromRaw}
	 */
	createKeyFromRaw(pem) {
		logger.debug('createKeyFromRaw - start');
        return new SM2Key(pem);
	}

	async importKey(pem) {

		if (!this._cryptoKeyStore) {
			throw new Error('importKey requires CryptoKeyStore to be set.');
		}

		// Attempt Key creation from Raw input
		const key = this.createKeyFromRaw(pem);
		await this._cryptoKeyStore.putKey(key);
		return key;
	}

	async getKey(ski) {

		if (!this._cryptoKeyStore) {
			throw new Error('getKey requires CryptoKeyStore to be set.');
		}
		const key = await this._cryptoKeyStore.getKey(ski);
		if (key instanceof SM2Key) {
			return key;
		}

		if (key) {
			return new SM2Key(key);
		}
	}

	/**
	 * This is an implementation of {@link module:api.CryptoSuite#getKeySize}
	 */
	getKeySize() {
		return 256;
	}

	/**
	 * This is an implementation of {@link module:api.CryptoSuite#hash}
	 * The opts argument is not supported.
	 */
	hash(msg, opts) {
		return this.msg;  // sm2_sm3: hash is done inside sign, so need to do this
	}

	/**
	 * This is an implementation of {@link module:api.CryptoSuite#sign}
	 * Signs digest using key.
	 */
	sign(key, data) {
		if (typeof key === 'undefined' || key === null) {
			throw new Error('A valid key is required to sign');
		}

		if (typeof digest === 'undefined' || digest === null) {
			throw new Error('A valid message is required to sign');
		}

		// Note that the statement below uses internal implementation specific to the
		// module './sm2/key.js'

        if (!key.isPrivate) 
            throw new Error('sign: must use a private key');

        const signer = new Signer(2, null, key._pem);
        const signature = signer.sign(Buffer.from(data));
        return Buffer.from(signature, 'base64');
    }

	verify(key, signature, data) {
		if (typeof key === 'undefined' || key === null) {
			throw new Error('A valid key is required to verify');
		}

		if (typeof signature === 'undefined' || signature === null) {
			throw new Error('A valid signature is required to verify');
		}

		if (typeof digest === 'undefined' || digest === null) {
			throw new Error('A valid message is required to verify');
		}

        if (key.isPrivate) 
            throw new Error('verify: must use a public key');

        const verifier = new Signer(2, key._pem);
        return verifier.verify(Buffer.from(data), signature.toString('base64'));
	}

	/**
	 * This is an implementation of {@link module:api.CryptoSuite#encrypt}
	 * To be implemented.
	 */
	encrypt(key, plainText, opts) {
		throw new Error('Not implemented yet');
	}

	/**
	 * This is an implementation of {@link module:api.CryptoSuite#decrypt}
	 * To be implemented.
	 */
	decrypt(key, cipherText, opts) {
		throw new Error('Not implemented yet');
	}
}

module.exports = CryptoSuite_SM2_SM4;
