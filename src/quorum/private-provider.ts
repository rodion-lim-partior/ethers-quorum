import axios from 'axios';
import https from 'https';
import { TransactionRequest, TransactionResponse } from '@ethersproject/abstract-provider';
import { Signer } from '@ethersproject/abstract-signer';
import { Networkish } from '@ethersproject/networks';
import { getDefaultProvider, JsonRpcProvider, Provider } from '@ethersproject/providers';
import { serialize as serializePublic, Transaction, UnsignedTransaction } from '@ethersproject/transactions';
import { ConnectionInfo, fetchJson } from '@ethersproject/web';
import { BigNumber } from 'ethers';
import {
  Bytes,
  BytesLike,
  deepCopy,
  Deferrable,
  defineReadOnly,
  hexlify,
  hexValue,
  isHexString,
  resolveProperties,
  shallowCopy,
} from 'ethers/lib/utils';

import { Logger } from '@ethersproject/logger';
import { version } from './_version';
import { parse, PrivacyOptions, PrivateTransaction, PrivateTransactionRequest, serialize } from './private-transaction';
import { PrivateSigner } from './private-wallet';

const logger = new Logger(version);
const errorGas = ['call', 'estimateGas'];

export const getDefaultPrivateProvider = (network?: Networkish, options?: any) => {
  if (network == null) {
    network = 'homestead';
  }

  // If passed a URL, figure out the right type of provider based on the scheme
  if (typeof network === 'string') {
    // Handle http and ws (and their secure variants)
    const match = network.match(/^(ws|http)s?:/i);
    if (match) {
      switch (match[1].toLowerCase()) {
        case 'http':
        case 'https':
          return new PrivateJsonRpcProvider(network);
        default:
          getDefaultProvider(network, options);
      }
    }
    getDefaultProvider(network, options);
  }
};

export interface PrivateProvider extends Provider {
  sendPrivateTransaction(
    transactionRequest: TransactionRequest,
    privacyOptions: PrivacyOptions,
  ): Promise<TransactionResponse>;
  sendRawPrivateTransaction(
    signedPrivateTransaction: string | Promise<string>,
    from: string,
    privacyOptions: PrivacyOptions,
  ): Promise<TransactionResponse>;
  getTesseraHash(data: BytesLike): Promise<string>;
}
export class PrivateJsonRpcProvider extends JsonRpcProvider implements PrivateProvider {
  readonly _tesseraUrl?: string;
  _privateEventLoopCache: Record<string, Promise<any> | null> = {};
  get _privateCache(): Record<string, Promise<any> | null> {
    if (this._privateEventLoopCache == null) {
      this._privateEventLoopCache = {};
    }
    return this._privateEventLoopCache;
  }

  constructor(url?: ConnectionInfo | string, network?: Networkish, tesseraUrl?: string) {
    super(url, network);
    this._tesseraUrl = tesseraUrl;
  }

  async getTesseraHash(data: BytesLike): Promise<string> {
    if (!this._tesseraUrl) {
      throw new Error('Invalid reference to a private transaction manager. Please check the tesseraUrl');
    }
    // data refers to the "data" attribute in a transaction
    if (typeof data !== 'string') {
      data = hexlify(data);
    }
    const encodedFunctionHash = Buffer.from(data.slice(2), 'hex').toString('base64');
    logger.debug('POST tessera ::', encodedFunctionHash);
    const res = await axios.post(
      `${this._tesseraUrl}/storeraw`,
      { payload: encodedFunctionHash },
      { httpsAgent: new https.Agent({ rejectUnauthorized: false }) },
    );
    return '0x' + Buffer.from(res.data.key, 'base64').toString('hex');
  }

  /**
   * Returns a private signer which can be used to sign both private and public transactions.
   * @param addressOrIndex            Address / index to use when signing a transaction
   * @param signerUrl                 External signer endpoint, non-mandatory when signing via unlocked geth keys
   * @param signerSignPrivateTxnRoute Route to append to external signer for signing a private transaction
   * @param signerSignPublicTxnRoute  Route to append to external signer for signing a public transaction
   * @returns
   */
  getPrivateSigner(
    addressOrIndex?: string | number,
    signerUrl?: string,
    signerSignPrivateTxnRoute?: string,
    signerSignPublicTxnRoute?: string,
  ): PrivateJsonRpcSigner {
    return new PrivateJsonRpcSigner(
      this,
      addressOrIndex,
      signerUrl,
      signerSignPrivateTxnRoute,
      signerSignPublicTxnRoute,
    );
  }

  // prettier-ignore
  async sendPrivateTransaction(transactionRequest: TransactionRequest, privacyOptions: PrivacyOptions): Promise<TransactionResponse> {
    await this.getNetwork();
    const blockNumber = await this._getInternalBlockNumber(100 + 2 * this.pollingInterval);
    const transaction = this._convertToPrivateTransaction(transactionRequest, privacyOptions);
    const wrappedTxn = transactionRequest as Transaction;
    try {
      const hash = await this.perform("sendPrivateTransaction", { transaction });
      wrappedTxn.hash = hash;
      return this._wrapTransaction(wrappedTxn, hash, blockNumber);
    } catch (error) {
      (error as any).transaction = wrappedTxn;
      (error as any).transactionHash = wrappedTxn.hash;
      throw error;
    }
  }

  // prettier-ignore
  async sendRawPrivateTransaction(signedTransaction: string | Promise<string>, from: string, privacyOptions: PrivacyOptions): Promise<TransactionResponse> {
    await this.getNetwork();
    const signedTransactionResolved = await Promise.resolve(signedTransaction)
    const hexTx = hexlify(signedTransactionResolved);
    const tx: any = parse(signedTransactionResolved); // this infers txn parameter from signed parameters, but there is an issue with deriving the right "from" from the signature and raw transaction
    if (tx.confirmations == null) { tx.confirmations = 0; }
    const blockNumber = await this._getInternalBlockNumber(100 + 2 * this.pollingInterval);
    try {
        const hash = await this.perform("sendRawPrivateTransaction", { signedTransaction: hexTx, privateFor: privacyOptions.privateFor });
        // back populate txn data since quorum deviates from ethereum -> workaround hack, better to get parse in transactions.ts working
        if (tx.from) {
          tx.from = from;
        }
        if (tx.chainId){
          tx.chainId = this._network
        }
        return this._wrapTransaction(tx, hash, blockNumber);
    } catch (error) {
        (error as any).transaction = tx;
        (error as any).transactionHash = tx.hash;
        throw error;
    }
  }

  // prettier-ignore
  async sendTransaction(signedTransaction: string | Promise<string>): Promise<TransactionResponse> {
    await this.getNetwork();
    const hexTx = await Promise.resolve(signedTransaction).then(t => hexlify(t));
    const tx = this.formatter.transaction(signedTransaction);
    if (tx.confirmations == null) { tx.confirmations = 0; }
    const blockNumber = await this._getInternalBlockNumber(100 + 2 * this.pollingInterval);
    try {
        const hash = await this.perform("sendTransaction", { signedTransaction: hexTx });
        return this._wrapTransaction(tx, hash, blockNumber);
    } catch (error) {
        (error as any).transaction = tx;
        (error as any).transactionHash = tx.hash;
        throw error;
    }
  }

  prepareRequest(method: string, params: any): [string, any[]] {
    switch (method) {
      case 'sendRawPrivateTransaction':
        const args: any = { privateFor: params.privateFor };
        if (params.privacyFlag) {
          args.privacyFlag = params.privacyFlag;
        }
        return ['eth_sendRawPrivateTransaction', [params.signedTransaction, args]];
      case 'sendPrivateTransaction':
        return ['eth_sendTransaction', [params.transaction]];
      default:
        return super.prepareRequest(method, params);
    }
  }

  async perform(method: string, params: any): Promise<any> {
    // Legacy networks do not like the type field being passed along (which
    // is fair), so we delete type if it is 0 and a non-EIP-1559 network
    if (method === 'call' || method === 'estimateGas') {
      const tx = params.transaction;
      if (tx && tx.type != null && BigNumber.from(tx.type).isZero()) {
        // If there are no EIP-1559 properties, it might be non-EIP-1559
        if (tx.maxFeePerGas == null && tx.maxPriorityFeePerGas == null) {
          const feeData = await this.getFeeData();
          if (feeData.maxFeePerGas == null && feeData.maxPriorityFeePerGas == null) {
            // Network doesn't know about EIP-1559 (and hence type)
            params = shallowCopy(params);
            params.transaction = shallowCopy(tx);
            delete params.transaction.type;
          }
        }
      }
    }

    const args = this.prepareRequest(method, params);

    if (args == null) {
      logger.throwError(method + ' not implemented', Logger.errors.NOT_IMPLEMENTED, { operation: method });
    }
    try {
      return await this.send(args[0], args[1]);
    } catch (error) {
      return checkError(method, error, params);
    }
  }

  send(method: string, params: any[]): Promise<any> {
    const request = {
      method,
      params,
      id: this._nextId++,
      jsonrpc: '2.0',
    };

    super.emit('debug', {
      action: 'request',
      request: deepCopy(request),
      provider: this,
    });

    // // We can expand this in the future to any call, but for now these
    // // are the biggest wins and do not require any serializing parameters.
    const cache = ['eth_chainId', 'eth_blockNumber'].indexOf(method) >= 0;
    if (cache && this._privateCache[method]) {
      return this._privateCache[method]!;
    }

    const result = fetchJson(this.connection, JSON.stringify(request), getResult).then(
      (result) => {
        this.emit('debug', {
          action: 'response',
          request,
          response: result,
          provider: this,
        });

        return result;
      },
      (error) => {
        this.emit('debug', {
          action: 'response',
          error,
          request,
          provider: this,
        });

        throw error;
      },
    );

    // // Cache the fetch, but clear it on the next event loop
    if (cache) {
      this._privateCache[method] = result;
      setTimeout(() => {
        this._privateCache[method] = null;
      }, 0);
    }

    return result;
  }

  _convertToPrivateTransaction(
    transactionRequest: TransactionRequest,
    privacyOptions: PrivacyOptions,
  ): PrivateTransaction {
    const result = transactionRequest as PrivateTransaction;
    const privateFor =
      typeof privacyOptions.privateFor === 'string' ? [privacyOptions.privateFor] : privacyOptions.privateFor;
    result.privateFor = privateFor;
    if (privacyOptions.privacyFlag) {
      result.privacyFlag = privacyOptions.privacyFlag;
    }
    if (transactionRequest.gasLimit) {
      result.gas = hexValue(transactionRequest.gasLimit);
    }
    if (transactionRequest.value) {
      result.value = hexValue(transactionRequest.value);
    }
    if (transactionRequest.nonce) {
      result.nonce = hexValue(transactionRequest.nonce);
    }
    const fieldsToRemove = ['chainId', 'gasPrice', 'gasLimit', 'type'];
    for (const field of fieldsToRemove) {
      if (field in result) {
        delete result[field as keyof PrivateTransaction];
      }
    }
    return result;
  }
}

function getResult(payload: { error?: { code?: number; data?: any; message?: string }; result?: any }): any {
  if (payload.error) {
    // @TODO: not any
    const error: any = new Error(payload.error.message);
    error.code = payload.error.code;
    error.data = payload.error.data;
    throw error;
  }

  return payload.result;
}

function spelunk(value: any, requireData: boolean): null | { message: string; data: null | string } {
  if (value == null) {
    return null;
  }

  // These *are* the droids we're looking for.
  if (typeof value.message === 'string' && value.message.match('reverted')) {
    const data = isHexString(value.data) ? value.data : null;
    if (!requireData || data) {
      return { message: value.message, data };
    }
  }

  // Spelunk further...
  if (typeof value === 'object') {
    for (const key in value) {
      const result = spelunk(value[key], requireData);
      if (result) {
        return result;
      }
    }
    return null;
  }

  // Might be a JSON string we can further descend...
  if (typeof value === 'string') {
    try {
      return spelunk(JSON.parse(value), requireData);
    } catch (error) {}
  }

  return null;
}

function checkError(method: string, error: any, params: any): any {
  const transaction = params.transaction || params.signedTransaction;

  // Undo the "convenience" some nodes are attempting to prevent backwards
  // incompatibility; maybe for v6 consider forwarding reverts as errors
  if (method === 'call') {
    const result = spelunk(error, true);
    if (result) {
      return result.data;
    }

    // Nothing descriptive..
    logger.throwError(
      'missing revert data in call exception; Transaction reverted without a reason string',
      Logger.errors.CALL_EXCEPTION,
      {
        data: '0x',
        transaction,
        error,
      },
    );
  }

  if (method === 'estimateGas') {
    // Try to find something, with a preference on SERVER_ERROR body
    let result = spelunk(error.body, false);
    if (result == null) {
      result = spelunk(error, false);
    }

    // Found "reverted", this is a CALL_EXCEPTION
    if (result) {
      logger.throwError(
        'cannot estimate gas; transaction may fail or may require manual gas limit',
        Logger.errors.UNPREDICTABLE_GAS_LIMIT,
        {
          reason: result.message,
          method,
          transaction,
          error,
        },
      );
    }
  }

  // @TODO: Should we spelunk for message too?

  let message = error.message;
  if (error.code === Logger.errors.SERVER_ERROR && error.error && typeof error.error.message === 'string') {
    message = error.error.message;
  } else if (typeof error.body === 'string') {
    message = error.body;
  } else if (typeof error.responseText === 'string') {
    message = error.responseText;
  }
  message = (message || '').toLowerCase();

  // "insufficient funds for gas * price + value + cost(data)"
  if (message.match(/insufficient funds|base fee exceeds gas limit/i)) {
    logger.throwError('insufficient funds for intrinsic transaction cost', Logger.errors.INSUFFICIENT_FUNDS, {
      error,
      method,
      transaction,
    });
  }

  // "nonce too low"
  if (message.match(/nonce (is )?too low/i)) {
    logger.throwError('nonce has already been used', Logger.errors.NONCE_EXPIRED, {
      error,
      method,
      transaction,
    });
  }

  // "replacement transaction underpriced"
  if (message.match(/replacement transaction underpriced|transaction gas price.*too low/i)) {
    logger.throwError('replacement fee too low', Logger.errors.REPLACEMENT_UNDERPRICED, {
      error,
      method,
      transaction,
    });
  }

  // "replacement transaction underpriced"
  if (message.match(/only replay-protected/i)) {
    logger.throwError('legacy pre-eip-155 transactions not supported', Logger.errors.UNSUPPORTED_OPERATION, {
      error,
      method,
      transaction,
    });
  }

  if (
    errorGas.indexOf(method) >= 0 &&
    message.match(/gas required exceeds allowance|always failing transaction|execution reverted/)
  ) {
    logger.throwError(
      'cannot estimate gas; transaction may fail or may require manual gas limit',
      Logger.errors.UNPREDICTABLE_GAS_LIMIT,
      {
        error,
        method,
        transaction,
      },
    );
  }

  throw error;
}
export class PrivateJsonRpcSigner extends Signer implements PrivateSigner {
  _index?: number;
  _address?: string;
  defaultSendRaw: boolean = false;
  readonly signerUrl?: string;
  readonly signerSignPrivateTxnRoute?: string; // url route to sign private transactions
  readonly signerSignPublicTxnRoute?: string; // url route to sign public transactions
  readonly provider!: PrivateJsonRpcProvider;

  constructor(
    provider: PrivateJsonRpcProvider,
    addressOrIndex?: string | number,
    signerUrl?: string,
    signerSignPrivateTxnRoute?: string,
    signerSignPublicTxnRoute?: string,
  ) {
    super();
    defineReadOnly(this, 'provider', provider);
    defineReadOnly(this, 'signerUrl', signerUrl);
    defineReadOnly(this, 'signerSignPrivateTxnRoute', signerSignPrivateTxnRoute || 'signer/private/hash');
    defineReadOnly(this, 'signerSignPublicTxnRoute', signerSignPublicTxnRoute || 'signer/public/hash');

    if (addressOrIndex == null) {
      addressOrIndex = 0;
    }

    if (typeof addressOrIndex === 'string') {
      defineReadOnly(this, '_address', this.provider.formatter.address(addressOrIndex));
      defineReadOnly(this, '_index', undefined);
    } else if (typeof addressOrIndex === 'number') {
      defineReadOnly(this, '_index', addressOrIndex);
      defineReadOnly(this, '_address', undefined);
    } else {
      logger.throwArgumentError('invalid address or index', 'addressOrIndex', addressOrIndex);
    }

    if (signerUrl) {
      this.defaultSendRaw = true; // When external signer is specified, transactions default to sendRawTransaction
    }
  }
  setDefaultSendRaw(val: boolean) {
    // Allows user to decide if default private transactions uses unlocked internal keys or gets forwarded to an external signer
    this.defaultSendRaw = val;
  }
  getAddress(): Promise<string> {
    if (this._address) {
      return Promise.resolve(this._address);
    }
    return this.provider.send('eth_accounts', []).then((accounts) => {
      if (accounts.length <= this._index!) {
        logger.throwError('unknown account #' + this._index, Logger.errors.UNSUPPORTED_OPERATION, {
          operation: 'getAddress',
        });
      }
      return this.provider.formatter.address(accounts[this._index!]);
    });
  }
  signMessage(message: string | Bytes): Promise<string> {
    throw new Error('Method not implemented.');
  }
  async signTransaction(transaction: Deferrable<TransactionRequest>): Promise<string> {
    if (!this.signerUrl) {
      throw new Error('External signer not specified.');
    }
    if (transaction.from != null) {
      delete transaction.from;
    }
    const utx = transaction as UnsignedTransaction;

    // TODO(rl): to remove axios and switch to default ethers web implementation
    let sig;
    try {
      sig = await axios.post(`${this.signerUrl}/${this.signerSignPublicTxnRoute}`, {
        unsignedTxnHash: serializePublic(utx),
        sender: (this._address && this._address.toLowerCase()) || this._address, // External signer should be case insensitive or take all lower case,
        chainId: utx.chainId,
      });
    } catch (error) {
      logger.throwError('Signing with external signer failed', undefined, {
        error,
        transaction,
      });
    }

    if (sig == undefined) throw new Error('Nil response from external signer');
    logger.debug('Signature ::', sig.data);

    return serializePublic(utx, {
      r: sig.data.r,
      s: sig.data.s,
      v: Number(sig.data.v),
    });
  }
  connect(provider: Provider): Signer {
    throw new Error('Method not implemented.');
  }
  async signPrivateTransaction(transaction: TransactionRequest): Promise<string> {
    if (!this.signerUrl) {
      throw new Error('External signer not specified.');
    }
    if (transaction.from != null) {
      delete transaction.from;
    }
    if (transaction.chainId != null) {
      delete transaction.chainId; // only pass in chainId for public transactions, this forces V in signature to be 37/38
    }
    const utx = transaction as UnsignedTransaction;

    // TODO(rl): to remove axios and switch to default ethers web implementation
    let sig;
    try {
      sig = await axios.post(`${this.signerUrl}/${this.signerSignPrivateTxnRoute}`, {
        unsignedTxnHash: serialize(utx),
        sender: (this._address && this._address.toLowerCase()) || this._address, // External signer should be case insensitive or take all lower case
      });
    } catch (error) {
      logger.throwError('Signing with external signer failed', undefined, {
        error,
        transaction,
      });
    }

    if (sig == undefined) throw new Error('Nil response from external signer');
    logger.debug('Signature ::', sig.data);

    return serialize(utx, {
      r: sig.data.r,
      s: sig.data.s,
      v: Number(sig.data.v), // 37/38 is for quorum private transactions, 27/28 for ethereum transactions
    });
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
    const tesseraHash = await this.provider.getTesseraHash(tx.data);
    logger.debug('Tessera hash ::', tesseraHash);
    // back populate tessera hash into the data attribute of the transaction
    tx.data = tesseraHash;
    const signedTx = await this.signPrivateTransaction(tx);
    return this.provider.sendRawPrivateTransaction(signedTx, from!, privacyOptions);
  }
  async sendPrivateTransaction(transaction: Deferrable<TransactionRequest>, privacyOptions: PrivacyOptions) {
    // TODO(rl): first transaction with nonce 0 throws error
    this._checkProvider('sendPrivateTransaction');
    const txn = await this.populateTransaction(transaction);
    return this.provider.sendPrivateTransaction(txn, privacyOptions);
  }
  async sendTransaction(transaction: Deferrable<PrivateTransactionRequest>): Promise<TransactionResponse> {
    this._checkProvider('sendTransaction');
    const transactionResolved = await resolveProperties(transaction);
    const transactionRequest = transactionResolved as TransactionRequest;
    let privateFor;
    if ('privateFor' in transactionRequest) {
      privateFor = transactionResolved.privateFor;
      delete transactionRequest['privateFor' as keyof TransactionRequest];
    }
    if (privateFor) {
      const privacyOptions = { privateFor };
      if (this.defaultSendRaw) {
        return this.sendRawPrivateTransaction(transactionRequest, privacyOptions);
      }
      return this.sendPrivateTransaction(transactionRequest, privacyOptions);
    } else {
      const tx = await this.populateTransaction(transactionRequest);
      const signedTx = await this.signTransaction(tx);
      return await this.provider.sendTransaction(signedTx);
    }
  }
  // TODO(rl): overwrite this so that we can override default gasLimit
  // populateTransaction(transaction: Deferrable<TransactionRequest>): Promise<TransactionRequest> {}
}
