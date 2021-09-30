import { GcpKmsAuthorizer } from '../src/auth/authorizer';
import { ICryptoKeyVersion } from '../src/types/interfaces/versionName';

import * as fcl from '@onflow/fcl';

// testnet

const apiUrl = 'https://access-testnet.onflow.org';

fcl.config().put('accessNode.api', apiUrl);

async function main() {
  const versionName: ICryptoKeyVersion = {
    projectId: 'kitty-items-31210',
    locationId: 'global',
    keyRingId: 'flow',
    keyId: 'flow-minter-key',
    versionId: '1',
  };

  const address = '0xfa5c16369bca3cfd';
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
  console.log(await fcl.tx(response).onceSealed());

  console.log('Transaction Succeeded');

  const publicKey = await authorizer.getPublicKey();

  const flowPublicKey = await authorizer.getFlowPublicKey();

  console.log(publicKey);

  console.log(flowPublicKey);
}

main().catch(e => console.error(e));
