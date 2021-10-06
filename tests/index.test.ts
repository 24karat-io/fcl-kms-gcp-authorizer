import { mocked } from 'ts-jest/utils';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { GcpKmsAuthorizer, ICryptoKeyVersion } from '../src/index';
import { Signer } from '../src/auth/signer';
import { Util } from './util';
import * as fcl from '@onflow/fcl';

const apiUrl = 'http://localhost:8080';

const publicKey =
  '8adf5d29ec027b64c1737e2cb1206143328c7792b98eb5a25203da20d34f5fa67848ccad9be5e2bc57ea5df3801a9ced02dd2faaa7a6ae902f18fde0d8aaef8a';
const flowPublicKey =
  'f847b8408adf5d29ec027b64c1737e2cb1206143328c7792b98eb5a25203da20d34f5fa67848ccad9be5e2bc57ea5df3801a9ced02dd2faaa7a6ae902f18fde0d8aaef8a02038203e8';
const privateKey =
  'e912bb5b687eba739da2a36dc8d121746c5809ae0fcab7e42f2562045fdad181';

jest.mock('@google-cloud/kms');

describe('GcpKmsAuthorizer', () => {
  test('should success', async () => {
    mocked(KeyManagementServiceClient).mockImplementation((): any => {
      return {
        getPublicKey: (_param: any, _callback: any) => {
          return { promise: () => '' };
        },
        sign: (_param: any, _callback: any) => {
          return { promise: () => '' };
        },
      };
    });
    jest.spyOn(Signer.prototype, 'sign').mockImplementation(
      (message: string): Promise<string> => {
        return new Promise((resolve, _reject) =>
          resolve(util.signWithKey(privateKey, message))
        );
      }
    );
    jest
      .spyOn(Signer.prototype, 'getPublicKey')
      .mockImplementation((): any => publicKey);
    jest
      .spyOn(Signer.prototype, 'getFlowPublicKey')
      .mockImplementation((): any => flowPublicKey);

    const util = new Util(apiUrl);
    const address = await util.createFlowAccount(flowPublicKey);
    const keyIndex = 0;

    const versionName: ICryptoKeyVersion = {
      projectId: 'tfc-dev-318510',
      locationId: 'global',
      keyRingId: 'flow',
      keyId: 'flow-minter-key',
      versionId: '1',
    };

    const authorizer = new GcpKmsAuthorizer(versionName);

    expect(await authorizer.getPublicKey()).toBe(publicKey);
    expect(await authorizer.getFlowPublicKey()).toBe(flowPublicKey);

    const authorization = authorizer.authorize(address, keyIndex);
    expect(typeof authorization).toBe('function');

    fcl.config().put('accessNode.api', apiUrl);
    const response = await fcl.send([
      fcl.transaction`
        transaction {
          prepare(signer: AuthAccount) {
            log("Test transaction signed by fcl-kms-authorizer")
          }
        }
      `,
      fcl.args([]),
      fcl.proposer(authorization),
      fcl.authorizations([authorization]),
      fcl.payer(authorization),
      fcl.limit(9999),
    ]);
    const res = await fcl.tx(response).onceSealed();
    expect(res.statusCode).toBe(0);
  });
});
