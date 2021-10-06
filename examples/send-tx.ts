import { GcpKmsAuthorizer } from '../src/auth/authorizer';

import * as fcl from '@onflow/fcl';

// emulator url
const apiUrl = 'http://localhost:8080';

fcl.config().put('accessNode.api', apiUrl);

async function main() {
  // Your GCP resourceId
  const resourceId: string =
    'projects/your-project-id/locations/global/keyRings/flow/cryptoKeys/flow-minter-key/cryptoKeyVersions/1';

  // Your account key (emulator or testnet)
  // Create account first using flow accounts create --key {yourRawHexPublicKey}
  const address = '0x01cf0e2f2f715450';
  const keyIndex = 0;

  const authorizer = new GcpKmsAuthorizer(resourceId);

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

  console.log('=====Transaction Succeeded=====\n');

  const publicKey = await authorizer.getPublicKey();

  const flowPublicKey = await authorizer.getFlowPublicKey();

  console.log('\nFetched Raw Hex Public Key: ' + publicKey);

  console.log('\nFetched Flow Public Key: ' + flowPublicKey + '\n');
}

main().catch(e => console.error(e));
