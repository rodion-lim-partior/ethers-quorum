'use strict';

import * as ethers from 'ethers';

/* tslint:disable:no-empty */
try {
  const anyGlobal = window as any;

  if (anyGlobal._ethers == null) {
    anyGlobal._ethers = ethers;
  }
} catch (error) {}

export { ethers };

export {
  getDefaultPrivateProvider,
  PrivateContractFactory,
  PrivateJsonRpcProvider,
  PrivateJsonRpcSigner,
  PrivateProvider,
  PrivateWallet,
} from './quorum';

export {
  Signer,
  Wallet,
  VoidSigner,
  getDefaultProvider,
  providers,
  BaseContract,
  Contract,
  ContractFactory,
  BigNumber,
  FixedNumber,
  constants,
  errors,
  logger,
  utils,
  wordlists,

  ////////////////////////
  // Compile-Time Constants
  version,

  ////////////////////////
  // Types
  ContractFunction,
  ContractReceipt,
  ContractTransaction,
  Event,
  EventFilter,
  Overrides,
  PayableOverrides,
  CallOverrides,
  PopulatedTransaction,
  ContractInterface,
  TypedDataDomain,
  TypedDataField,
  BigNumberish,
  Bytes,
  BytesLike,
  Signature,
  Transaction,
  UnsignedTransaction,
  Wordlist,
} from 'ethers';
