import { Signer } from '@ethersproject/abstract-signer';
import { getAddress } from '@ethersproject/address';
import { TransactionRequest, TransactionResponse } from '@ethersproject/abstract-provider';
import { keccak256 } from '@ethersproject/keccak256';
import { resolveProperties } from '@ethersproject/properties';
import { serialize, UnsignedTransaction } from '@ethersproject/transactions';
import { Wallet } from '@ethersproject/wallet';
import { Deferrable } from 'ethers/lib/utils';
import { logger } from 'ethers';

import { PrivateProvider } from './private-provider';
import { PrivacyOptions, PrivateTransactionRequest } from './private-transaction';

export interface PrivateSigner extends Signer {
  readonly provider: PrivateProvider;
  defaultSendRaw: boolean; // Route to an external signer instead of relying on unlocked internal keys

  setDefaultSendRaw(val: boolean): void;
  signPrivateTransaction(transaction: TransactionRequest): Promise<string>;
  // Rely on unlocked geth keys
  sendPrivateTransaction(transaction: TransactionRequest, privacyOptions: PrivacyOptions): Promise<TransactionResponse>;
  // Rely on external signer
  sendRawPrivateTransaction(
    transaction: TransactionRequest,
    privacyOptions: PrivacyOptions,
  ): Promise<TransactionResponse>;
  sendTransaction(transaction: PrivateTransactionRequest): Promise<TransactionResponse>;
}

export class PrivateWallet extends Wallet implements PrivateSigner {
  readonly provider!: PrivateProvider;
  defaultSendRaw: boolean = true;

  setDefaultSendRaw(val: boolean) {
    // Allows user to decide if default private transactions uses unlocked internal keys or gets forwarded to an external signer
    this.defaultSendRaw = val;
  }
  async sendPrivateTransaction(transaction: Deferrable<TransactionRequest>, privacyOptions: PrivacyOptions) {
    this._checkProvider('sendPrivateTransaction');
    const txn = await this.populateTransaction(transaction);
    return this.provider.sendPrivateTransaction(txn, privacyOptions);
  }

  async sendRawPrivateTransaction(
    transaction: Deferrable<TransactionRequest>,
    privacyOptions: PrivacyOptions,
  ): Promise<TransactionResponse> {
    this._checkProvider('sendRawPrivateTransaction');
    const tx = await this.populateTransaction(transaction);
    const from = tx.from;
    // submit transaction data to tessera
    if (!tx.data) {
      throw new Error('Transaction has no data to sign');
    }
    logger.debug('Unsigned transaction', tx);
    const tesseraHash = await this.provider.getTesseraHash(tx.data);
    tx.data = tesseraHash;
    const signedTx = await this.signPrivateTransaction(tx);
    return this.provider.sendRawPrivateTransaction(signedTx, from!, privacyOptions);
  }

  async sendTransaction(transaction: Deferrable<PrivateTransactionRequest>): Promise<TransactionResponse> {
    this._checkProvider('sendTransaction');
    const transactionResolved = await resolveProperties(transaction);
    const transactionRequest = transactionResolved as TransactionRequest;
    const privacyArgs: any = {};
    for (const k of ['privateFor', 'privacyFlag']) {
      if (k in transactionRequest) {
        delete transactionRequest[k as keyof TransactionRequest];
        privacyArgs[k] = transactionResolved[k as keyof PrivateTransactionRequest];
      }
    }
    if (transactionResolved.privateFor) {
      return this.sendPrivateTransaction(transactionRequest, privacyArgs);
    } else {
      const tx = await this.populateTransaction(transactionRequest);
      const signedTx = await this.signTransaction(tx);
      return await this.provider.sendTransaction(signedTx);
    }
  }

  signPrivateTransaction(transaction: TransactionRequest): Promise<string> {
    return resolveProperties(transaction).then((tx) => {
      if (tx.from != null) {
        if (getAddress(tx.from) !== this.address) {
          throw new Error('transaction from address mismatch');
        }
        delete tx.from;
      }
      if (tx.chainId != null) {
        delete tx.chainId; // only pass in chainId for public transactions, this forces V in signature to be 37/38
      }
      const utx = tx as UnsignedTransaction;
      const signature = this._signingKey().signDigest(keccak256(serialize(utx)));
      signature.v = signature.v - 27 + 37;
      return serialize(utx, signature);
    });
  }
}
