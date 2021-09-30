import { GcpKmsAuthorizer } from '../src/auth/authorizer';
import { ICryptoKeyVersion } from '../src/types/interfaces/versionName';

import * as fcl from '@onflow/fcl';

// emulator url
const apiUrl = 'http://localhost:8080';

fcl.config().put('accessNode.api', apiUrl);

async function main() {
  // Your GCP resourceId data
  const versionName: ICryptoKeyVersion = {
    projectId: 'my-project-id',
    locationId: 'global',
    keyRingId: 'flow',
    keyId: 'flow-minter-key',
    versionId: '1',
  };

  // Your account key (emulator or testnet)
  const address = '0x179b6b1cb6755e31';
  const keyIndex = 0;

  const authorizer = new GcpKmsAuthorizer(versionName);

  const authorization = authorizer.authorize(address, keyIndex);

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

  console.log('Transaction Succeeded');

  const publicKey = await authorizer.getPublicKey();

  const flowPublicKey = await authorizer.getFlowPublicKey();

  console.log(publicKey);

  console.log(flowPublicKey);
}

main().catch(e => console.error(e));
