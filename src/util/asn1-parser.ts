import { google } from '@google-cloud/kms/build/protos/protos';
import { fromBER, Sequence, BitString, Integer } from 'asn1js';
import { stringToArrayBuffer, fromBase64 } from 'pvutils';
import { Buffer } from 'buffer';

export function toArrayBuffer(buffer: Buffer) {
  const ab = new ArrayBuffer(buffer.length);
  const view = new Uint8Array(ab);
  for (let i = 0; i < buffer.length; ++i) {
    view[i] = buffer[i];
  }
  return ab;
}

export function parsePublicKey(publicKey: google.cloud.kms.v1.IPublicKey) {
  // Remove pem format header and footer
  const keyString = publicKey.pem
    ?.replace('-----BEGIN PUBLIC KEY-----\n', '')
    .replace('\n-----END PUBLIC KEY-----\n', '')
    .replace('\n', '');
  if (keyString) {
    const { result } = fromBER(stringToArrayBuffer(fromBase64(keyString)));

    if (publicKey.pem) {
      const values = (result as Sequence).valueBlock.value;
      const value = values[1] as BitString;
      return Buffer.from(value.valueBlock.valueHex.slice(1));
    }
  }
  return undefined;
}

export function parseSignature(buf: Buffer) {
  const { result } = fromBER(toArrayBuffer(buf));
  const values = (result as Sequence).valueBlock.value;

  const getHex = (value: Integer) => {
    const buf = Buffer.from(value.valueBlock.valueHex);
    return buf.slice(Math.max(buf.length - 32, 0));
  };

  const r = _pad32(getHex(values[0] as Integer));
  const s = _pad32(getHex(values[1] as Integer));
  return { r, s };
}

export function _pad32(buf: Buffer): Buffer {
  const paddedBuf = Buffer.alloc(32);
  buf.copy(paddedBuf, paddedBuf.length - buf.length);
  return paddedBuf;
}
