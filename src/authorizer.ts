import * as fcl from '@onflow/fcl';
import { Signer } from './signer';
import { ClientOptions } from 'google-gax';
import { ICryptoKeyVersion } from './interfaces/versionName';
import { IAuthorize } from './interfaces/authorize';

export class GcpKmsAuthorizer {
  private readonly signer: Signer;

  public constructor(
    versionName: ICryptoKeyVersion,
    clientOptions?: ClientOptions
  ) {
    this.signer = new Signer(versionName, clientOptions);
  }

  public async getPublicKey(): Promise<string | undefined> {
    return await this.signer.getPublicKey();
  }

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
