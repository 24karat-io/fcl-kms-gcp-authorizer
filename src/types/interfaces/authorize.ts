export interface IAuthorize {
  account?: object;
  tempId: string;
  addr: string;
  keyId: number;
  resolve: null;
  signingFunction: Function;
}
