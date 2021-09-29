import { KeyManagementServiceClient } from '@google-cloud/kms';
import { ClientOptions } from 'google-gax';

import { parseSignature, parsePublicKey } from '../util/asn1-parser';
import { SHA3 } from 'sha3';
import { google } from '@google-cloud/kms/build/protos/protos';
import { ICryptoKeyVersion } from '../interfaces/versionName';
/**
 * Contains functions that are used to call and process GCP KMS Client message signing and key fetching.
 */
export class Signer {
  private readonly client: KeyManagementServiceClient;
  private readonly versionName: string;
  /**
   * Creates a new Signer instance
   * @param versionName Google KMS Client parameters (used for client.cryptoKeyVersionPath)
   * @param clientOptions Google KMS Client Options
   */
  public constructor(
    versionName: ICryptoKeyVersion,
    clientOptions?: ClientOptions
  ) {
    const { projectId, locationId, keyRingId, keyId, versionId } = versionName;
    this.client = new KeyManagementServiceClient(clientOptions);
    this.versionName = this.client.cryptoKeyVersionPath(
      projectId,
      locationId,
      keyRingId,
      keyId,
      versionId
    );
  }
  /**
   * Fetches public key from the GCP KMS Client and asn1 decodes it.
   * @returns a promise string public key in raw hex format
   */
  public async getPublicKey(): Promise<string | undefined> {
    const asn1PublicKey = await this._getPublicKey();
    const publicKey = parsePublicKey(asn1PublicKey);
    return publicKey?.toString('hex').replace(/^04/, '');
  }

  /**
   * Hashes message using SHA3_256
   * @param message message to be hashed
   * @returns message sha digest
   */
  private _hashMessage(message: string): Buffer {
    const sha = new SHA3(256);
    sha.update(Buffer.from(message, 'hex'));
    return sha.digest();
  }
  /**
   * Fetches public key from google client
   * @returns returns google client public key
   */
  private async _getPublicKey(): Promise<google.cloud.kms.v1.IPublicKey> {
    const [publicKey] = await this.client.getPublicKey({
      name: this.versionName,
    });

    // For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
    // https://cloud.google.com/kms/docs/data-integrity-guidelines
    var crc32c = require('fast-crc32c');
    if (publicKey.name !== this.versionName) {
      throw new Error('GetPublicKey: request corrupted in-transit');
    }
    if (
      crc32c.calculate(publicKey.pem) !== Number(publicKey.pemCrc32c?.value)
    ) {
      throw new Error('GetPublicKey: response corrupted in-transit');
    }
    return publicKey;
  }

  /**
   * Signs message using GCP KMS Client and parses the signature
   * @param message message to be signed
   * @returns hex encoded signed message string
   */
  public async sign(message: string): Promise<string | undefined> {
    const digest = this._hashMessage(message);
    const asn1Signature = await this._sign(digest);
    if (asn1Signature) {
      const { r, s } = parseSignature(asn1Signature);
      return Buffer.concat([r, s]).toString('hex');
    }
    return undefined;
  }
  /**
   * Signs message digest using GCP KMS Client
   * @param digest sha message digest
   * @returns signResponse Buffer
   */
  private async _sign(digest: Buffer): Promise<Buffer | undefined> {
    var crc32c = require('fast-crc32c');
    const digestCrc32c = crc32c.calculate(digest);
    const [signResponse] = await this.client.asymmetricSign({
      name: this.versionName,
      digest: {
        sha256: digest,
      },
      digestCrc32c: {
        value: digestCrc32c,
      },
    });

    // Optional, but recommended: perform integrity verification on signResponse.
    // For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
    // https://cloud.google.com/kms/docs/data-integrity-guidelines
    if (signResponse.name !== this.versionName) {
      throw new Error('AsymmetricSign: request corrupted in-transit');
    }
    if (!signResponse.verifiedDigestCrc32c) {
      throw new Error('AsymmetricSign: request corrupted in-transit');
    }
    if (
      crc32c.calculate(signResponse.signature) !==
      Number(signResponse.signatureCrc32c?.value)
    ) {
      throw new Error('AsymmetricSign: response corrupted in-transit');
    }

    if (signResponse.signature) return Buffer.from(signResponse.signature);
    return undefined;
  }
}
