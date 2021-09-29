import * as fcl from '@onflow/fcl';
import { Signer } from './signer';
import { ClientOptions } from 'google-gax';
import { ICryptoKeyVersion } from '../interfaces/versionName';
import { IAuthorize } from '../interfaces/authorize';

/**
 * Provides GCP KMS Authorization functions.
 */
export class GcpKmsAuthorizer {
  private readonly signer: Signer;

  /**
   * Creates a new GCP KMS Authorizer instance
   * @param versionName Google KMS Client parameters (used for client.cryptoKeyVersionPath)
   * @param clientOptions Google KMS Client Options
   */
  public constructor(
    versionName: ICryptoKeyVersion,
    clientOptions?: ClientOptions
  ) {
    this.signer = new Signer(versionName, clientOptions);
  }

  /**
   * Used to fetch the public key from the GCP KMS Client
   * @returns a promise string public key in raw hex format
   */
  public async getPublicKey(): Promise<string | undefined> {
    return await this.signer.getPublicKey();
  }

  /**
   * Creates an authorization object using the GCP KMS client signing function.
   * @param fromAddress addres of flow account that signs the transaction
   * @param keyIndex index of the the key used to sign
   * @returns
   */
  public authorize(fromAddress: string, keyIndex: number) {
    return async (account: any = {}): Promise<IAuthorize> => {
      return {
        ...account,
        tempId: [fromAddress, keyIndex].join('-'),
        addr: fcl.sansPrefix(fromAddress),
        keyId: Number(keyIndex),
        resolve: null,
        signingFunction: async (data: any) => {
          return {
            addr: fcl.withPrefix(fromAddress),
            keyId: Number(keyIndex),
            signature: await this.signer.sign(data.message),
          };
        },
      };
    };
  }
}
