'use strict';

import * as ethers from 'ethers';
import * as ethers_quorum from './quorum';

/* tslint:disable:no-empty */
try {
  const anyGlobal = window as any;

  if (anyGlobal._ethers == null) {
    anyGlobal._ethers = ethers;
  }
} catch (error) {}

export {
  getDefaultPrivateProvider,
  PrivateContract,
  PrivateContractFactory,
  PrivateJsonRpcProvider,
  PrivateJsonRpcSigner,
  PrivateProvider,
  PrivateWallet,
} from './quorum';

(ethers as any).PrivateWallet = ethers_quorum.PrivateWallet;
(ethers as any).PrivateJsonRpcProvider = ethers_quorum.PrivateJsonRpcProvider;
(ethers as any).PrivateJsonRpcSigner = ethers_quorum.PrivateJsonRpcSigner;
(ethers as any).PrivateContract = ethers_quorum.PrivateContract;
(ethers as any).PrivateContractFactory = ethers_quorum.PrivateContractFactory;
(ethers as any).getDefaultPrivateProvider = ethers_quorum.getDefaultPrivateProvider;

export { ethers };

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
