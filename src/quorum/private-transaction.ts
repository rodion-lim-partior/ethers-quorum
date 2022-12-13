import { BigNumber, BigNumberish } from 'ethers';
import {
  accessListify,
  AccessListish,
  arrayify,
  checkProperties,
  getAddress,
  hexConcat,
  hexZeroPad,
  keccak256,
  recoverAddress,
} from 'ethers/lib/utils';
import {
  BytesLike,
  DataOptions,
  hexlify,
  isBytesLike,
  SignatureLike,
  splitSignature,
  stripZeros,
} from '@ethersproject/bytes';
import { Zero } from '@ethersproject/constants';
import * as RLP from '@ethersproject/rlp';
import { Transaction, UnsignedTransaction } from '@ethersproject/transactions';

import { Logger } from '@ethersproject/logger';
import { version } from './_version';
const logger = new Logger(version);

export enum PrivacyFlag {
  None = 0,
  PP = 1,
  MP = 2,
  PSV = 3,
}

export interface PrivacyOptions {
  privateFor: string | string[];
  privacyFlag?: PrivacyFlag;
}

export interface PrivateTransaction {
  publicHash?: string;
  privateHash?: string;
  from: string;
  to?: string;
  nonce?: string;
  gas?: string;
  data?: string;
  input?: string; // input cannot co-exist with data if they are set to different values. input is the new naming of data. They are the same parameters, but both remain for backwards compatibility.
  value: string;
  privateFor: string | string[];
  privacyFlag?: PrivacyFlag;
}

export type PrivateTransactionRequest = {
  to?: string;
  from?: string;
  nonce?: BigNumberish;

  gasLimit?: BigNumberish;
  gasPrice?: BigNumberish;

  data?: BytesLike;
  value?: BigNumberish;
  chainId?: number;

  type?: number;
  accessList?: AccessListish;

  maxPriorityFeePerGas?: BigNumberish;
  maxFeePerGas?: BigNumberish;

  customData?: Record<string, any>;
  ccipReadEnabled?: boolean;

  privateFor: string | string[];
  privacyFlag?: PrivacyFlag;
};

const allowedTransactionKeys: { [key: string]: boolean } = {
  chainId: true,
  data: true,
  gasLimit: true,
  gasPrice: true,
  nonce: true,
  to: true,
  type: true,
  value: true,
};

// Legacy Transaction Fields
const transactionFields = [
  { name: 'nonce', maxLength: 32, numeric: true },
  { name: 'gasPrice', maxLength: 32, numeric: true },
  { name: 'gasLimit', maxLength: 32, numeric: true },
  { name: 'to', length: 20 },
  { name: 'value', maxLength: 32, numeric: true },
  { name: 'data' },
];

// Legacy Transactions and EIP-155
function _serialize(transaction: UnsignedTransaction, signature?: SignatureLike): string {
  checkProperties(transaction, allowedTransactionKeys);

  const raw: (string | Uint8Array)[] = [];

  transactionFields.forEach(function (fieldInfo) {
    let value = (transaction as any)[fieldInfo.name] || [];
    const options: DataOptions = {};
    if (fieldInfo.numeric) {
      options.hexPad = 'left';
    }
    value = arrayify(hexlify(value, options));

    // Fixed-width field
    if (fieldInfo.length && value.length !== fieldInfo.length && value.length > 0) {
      logger.throwArgumentError('invalid length for ' + fieldInfo.name, 'transaction:' + fieldInfo.name, value);
    }

    // Variable-width (with a maximum)
    if (fieldInfo.maxLength) {
      value = stripZeros(value);
      if (value.length > fieldInfo.maxLength) {
        logger.throwArgumentError('invalid length for ' + fieldInfo.name, 'transaction:' + fieldInfo.name, value);
      }
    }

    raw.push(hexlify(value));
  });

  let chainId = 0;
  if (transaction.chainId != null) {
    // A chainId was provided; if non-zero we'll use EIP-155
    chainId = transaction.chainId;

    if (typeof chainId !== 'number') {
      logger.throwArgumentError('invalid transaction.chainId', 'transaction', transaction);
    }
  } else if (signature && !isBytesLike(signature) && signature.v && signature.v > 28) {
    chainId = 0;
    // No chainId provided, but the signature is signing with EIP-155; derive chainId
    // chainId = Math.floor((signature.v - 35) / 2);
  }

  // We have an EIP-155 transaction (chainId was specified and non-zero)
  if (chainId !== 0) {
    raw.push(hexlify(chainId)); // @TODO: hexValue?
    raw.push('0x');
    raw.push('0x');
  }

  // Requesting an unsigned transaction
  if (!signature) {
    return RLP.encode(raw);
  }

  // The splitSignature will ensure the transaction has a recoveryParam in the
  // case that the signTransaction function only adds a v.
  const sig = splitSignature(signature);

  // We pushed a chainId and null r, s on for hashing only; remove those
  let v = 37 + sig.recoveryParam;
  if (chainId !== 0) {
    raw.pop();
    raw.pop();
    raw.pop();
    v += chainId * 2 + 8;

    // // If an EIP-155 v (directly or indirectly; maybe _vs) was provided, check it!
    if (sig.v > 28 && sig.v !== v) {
      logger.throwArgumentError('transaction.chainId/signature.v mismatch', 'signature', signature);
    }
  } else if (sig.v !== v) {
    logger.throwArgumentError('transaction.chainId/signature.v mismatch', 'signature', signature);
  }

  raw.push(hexlify(v));
  raw.push(stripZeros(arrayify(sig.r)));
  raw.push(stripZeros(arrayify(sig.s)));

  return RLP.encode(raw);
}

export function serialize(transaction: UnsignedTransaction, signature?: SignatureLike): string {
  // Legacy and EIP-155 Transactions
  if (transaction.type == null || transaction.type === 0) {
    if (transaction.accessList != null) {
      logger.throwArgumentError(
        'untyped transactions do not support accessList; include type: 1',
        'transaction',
        transaction,
      );
    }
    return _serialize(transaction, signature);
  }

  // Typed Transactions (EIP-2718)
  switch (transaction.type) {
    case 1:
      return _serializeEip2930(transaction, signature);
    case 2:
      return _serializeEip1559(transaction, signature);
    default:
      break;
  }

  return logger.throwError(`unsupported transaction type: ${transaction.type}`, Logger.errors.UNSUPPORTED_OPERATION, {
    operation: 'serializeTransaction',
    transactionType: transaction.type,
  });
}

function _serializeEip1559(transaction: UnsignedTransaction, signature?: SignatureLike): string {
  // If there is an explicit gasPrice, make sure it matches the
  // EIP-1559 fees; otherwise they may not understand what they
  // think they are setting in terms of fee.
  if (transaction.gasPrice != null) {
    const gasPrice = BigNumber.from(transaction.gasPrice);
    const maxFeePerGas = BigNumber.from(transaction.maxFeePerGas || 0);
    if (!gasPrice.eq(maxFeePerGas)) {
      logger.throwArgumentError('mismatch EIP-1559 gasPrice != maxFeePerGas', 'tx', {
        gasPrice,
        maxFeePerGas,
      });
    }
  }

  const fields: any = [
    formatNumber(transaction.chainId || 0, 'chainId'),
    formatNumber(transaction.nonce || 0, 'nonce'),
    formatNumber(transaction.maxPriorityFeePerGas || 0, 'maxPriorityFeePerGas'),
    formatNumber(transaction.maxFeePerGas || 0, 'maxFeePerGas'),
    formatNumber(transaction.gasLimit || 0, 'gasLimit'),
    transaction.to != null ? getAddress(transaction.to) : '0x',
    formatNumber(transaction.value || 0, 'value'),
    transaction.data || '0x',
    formatAccessList(transaction.accessList || []),
  ];

  if (signature) {
    const sig = splitSignature(signature);
    fields.push(formatNumber(sig.recoveryParam, 'recoveryParam'));
    fields.push(stripZeros(sig.r));
    fields.push(stripZeros(sig.s));
  }

  return hexConcat(['0x02', RLP.encode(fields)]);
}

function _serializeEip2930(transaction: UnsignedTransaction, signature?: SignatureLike): string {
  const fields: any = [
    formatNumber(transaction.chainId || 0, 'chainId'),
    formatNumber(transaction.nonce || 0, 'nonce'),
    formatNumber(transaction.gasPrice || 0, 'gasPrice'),
    formatNumber(transaction.gasLimit || 0, 'gasLimit'),
    transaction.to != null ? getAddress(transaction.to) : '0x',
    formatNumber(transaction.value || 0, 'value'),
    transaction.data || '0x',
    formatAccessList(transaction.accessList || []),
  ];

  if (signature) {
    const sig = splitSignature(signature);
    fields.push(formatNumber(sig.recoveryParam, 'recoveryParam'));
    fields.push(stripZeros(sig.r));
    fields.push(stripZeros(sig.s));
  }

  return hexConcat(['0x01', RLP.encode(fields)]);
}

function formatNumber(value: BigNumberish, name: string): Uint8Array {
  const result = stripZeros(BigNumber.from(value).toHexString());
  if (result.length > 32) {
    logger.throwArgumentError('invalid length for ' + name, 'transaction:' + name, value);
  }
  return result;
}

function formatAccessList(value: AccessListish): [string, string[]][] {
  return accessListify(value).map((set) => [set.address, set.storageKeys]);
}

function handleNumber(value: string): BigNumber {
  if (value === '0x') {
    return Zero;
  }
  return BigNumber.from(value);
}

function handleAddress(value: string): string | undefined {
  if (value === '0x') {
    return undefined;
  }
  return getAddress(value);
}

export function parse(rawTransaction: BytesLike): Transaction {
  // Custom private transaction parser, derive transaction from signed rlp txn
  const transaction = RLP.decode(rawTransaction);
  if (transaction.length !== 9) {
    logger.throwArgumentError(
      `invalid raw transaction. Has ${transaction.length} fields, expecting ${9}`,
      'rawTransaction',
      rawTransaction,
    );
  }

  const tx: Transaction = {
    nonce: handleNumber(transaction[0]).toNumber(),
    gasPrice: handleNumber(transaction[1]),
    gasLimit: handleNumber(transaction[2]),
    to: handleAddress(transaction[3]),
    value: handleNumber(transaction[4]),
    data: transaction[5],
    chainId: 0,
  };

  try {
    tx.v = BigNumber.from(transaction[6]).toNumber();
  } catch (error) {
    logger.warn(error);
    return tx;
  }

  tx.r = hexZeroPad(transaction[7], 32);
  tx.s = hexZeroPad(transaction[8], 32);

  if (BigNumber.from(tx.r).isZero() && BigNumber.from(tx.s).isZero()) {
    // EIP-155 unsigned transaction
    tx.chainId = tx.v = 0;
  } else {
    // Signed Transaction
    // tx.chainId = Math.floor((tx.v - 35) / 2);
    // if (tx.chainId < 0) {
    //   tx.chainId = 0;
    // }

    tx.chainId = 0; // chainId is not passed in for private transactions

    let recoveryParam = tx.v - 37;

    if (tx.chainId !== 0) {
      transaction[6] = hexlify(tx.chainId);
      transaction[7] = '0x';
      transaction[8] = '0x';
      recoveryParam -= tx.chainId * 2 + 8;
    }

    const digest = keccak256(RLP.encode(transaction));
    try {
      tx.from = recoverAddress(digest, {
        r: hexlify(tx.r),
        s: hexlify(tx.s),
        recoveryParam,
      });
    } catch (error) {
      logger.warn(error);
    }
  }
  tx.hash = keccak256(rawTransaction);
  return tx;
}
