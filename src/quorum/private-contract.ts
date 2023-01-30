import { checkResultErrors, EventFragment, Indexed, Interface, ParamType } from '@ethersproject/abi';
import {
  BlockTag,
  Listener,
  Filter,
  FilterByBlockHash,
  Log,
  Provider,
  TransactionRequest,
} from '@ethersproject/abstract-provider';
import { Signer, VoidSigner } from '@ethersproject/abstract-signer';
import { TransactionReceipt, TransactionResponse } from '@ethersproject/abstract-provider';
import { getContractAddress } from '@ethersproject/address';
import { BigNumber, BigNumberish } from '@ethersproject/bignumber';
import { BytesLike, concat, hexlify, isBytes, isHexString } from '@ethersproject/bytes';
import { Contract, ContractFunction, ContractInterface, Event, EventFilter } from '@ethersproject/contracts';
import { Logger } from '@ethersproject/logger';
import {
  accessListify,
  arrayify,
  deepCopy,
  defineReadOnly,
  Deferrable,
  FunctionFragment,
  getAddress,
  getStatic,
  LogDescription,
  resolveProperties,
  shallowCopy,
} from 'ethers/lib/utils';
import { CallOverrides, PopulatedTransaction } from 'ethers';

import { PrivateProvider } from './private-provider';
import { PrivateSigner } from './private-wallet';
import { version } from './_version';
import { PrivacyFlag, PrivacyOptions, PrivateTransactionRequest } from './private-transaction';

const logger = new Logger(version);

export interface ContractReceipt extends TransactionReceipt {
  events?: Event[];
}
export interface CallOverrides2 extends CallOverrides {
  privateFor?: string | string[];
  privacyFlag?: PrivacyFlag;
}

type InterfaceFunc = (contractInterface: ContractInterface) => Interface;

const allowedTransactionKeys: { [key: string]: boolean } = {
  chainId: true,
  data: true,
  from: true,
  gasLimit: true,
  gasPrice: true,
  nonce: true,
  to: true,
  value: true,
  type: true,
  accessList: true,
  maxFeePerGas: true,
  maxPriorityFeePerGas: true,
  customData: true,
  ccipReadEnabled: true,
};

export class PrivateContractFactory {
  readonly interface!: Interface;
  readonly bytecode!: string;
  readonly signer!: PrivateSigner;

  constructor(contractInterface: ContractInterface, bytecode: BytesLike | { object: string }, signer: PrivateSigner) {
    let bytecodeHex: string | null = null;

    if (typeof bytecode === 'string') {
      bytecodeHex = bytecode;
    } else if (isBytes(bytecode)) {
      bytecodeHex = hexlify(bytecode);
    } else if (bytecode && typeof bytecode.object === 'string') {
      // Allow the bytecode object from the Solidity compiler
      bytecodeHex = (bytecode as any).object;
    } else {
      // Crash in the next verification step
      bytecodeHex = '!';
    }

    // Make sure it is 0x prefixed
    if (bytecodeHex!.substring(0, 2) !== '0x') {
      bytecodeHex = '0x' + bytecodeHex;
    }

    // Make sure the final result is valid bytecode
    if (!isHexString(bytecodeHex) || bytecodeHex!.length % 2) {
      logger.throwArgumentError('invalid bytecode', 'bytecode', bytecode);
    }

    // If we have a signer, make sure it is valid
    if (signer && !Signer.isSigner(signer)) {
      logger.throwArgumentError('invalid signer', 'signer', signer);
    }

    defineReadOnly(this, 'bytecode', bytecodeHex!);
    defineReadOnly(this, 'interface', getStatic<InterfaceFunc>(new.target, 'getInterface')(contractInterface));
    defineReadOnly(this, 'signer', signer || undefined);
  }

  // @TODO: Future; rename to populateTransaction?
  getDeployTransaction(...args: any[]): TransactionRequest {
    let tx: TransactionRequest = {};

    // If we have 1 additional argument, we allow transaction overrides
    if (args.length === this.interface.deploy.inputs.length + 1 && typeof args[args.length - 1] === 'object') {
      tx = shallowCopy(args.pop());
      for (const key in tx) {
        if (!allowedTransactionKeys[key]) {
          throw new Error('unknown transaction override ' + key);
        }
      }
    }

    // Do not allow these to be overridden in a deployment transaction
    ['data', 'from', 'to'].forEach((key) => {
      if ((tx as any)[key] == null) {
        return;
      }
      logger.throwError('cannot override ' + key, Logger.errors.UNSUPPORTED_OPERATION, { operation: key });
    });

    if (tx.value) {
      const value = BigNumber.from(tx.value);
      if (!value.isZero() && !this.interface.deploy.payable) {
        logger.throwError('non-payable constructor cannot override value', Logger.errors.UNSUPPORTED_OPERATION, {
          operation: 'overrides.value',
          value: tx.value,
        });
      }
    }

    // Make sure the call matches the constructor signature
    logger.checkArgumentCount(args.length, this.interface.deploy.inputs.length, ' in Contract constructor');

    // Set the data to the bytecode + the encoded constructor arguments
    tx.data = hexlify(concat([this.bytecode, this.interface.encodeDeploy(args)]));

    return tx;
  }

  async deploy(...args: any[]): Promise<PrivateContract> {
    const privacyOptions: PrivacyOptions = {} as any;
    let last: any;
    if (args.length > 0 && args.slice(-1)) {
      last = args[args.length - 1];
      if (typeof last === 'object' && 'privateFor' in last) {
        last = { ...last };
        privacyOptions.privateFor = last.privateFor;
        delete last.privateFor;
        if ('privacyFlag' in last) {
          privacyOptions.privacyFlag = last.privacyFlag;
          delete last.privacyFlag;
        }
      }
    }

    let overrides: any = {};

    // If 1 extra parameter was passed in, it contains overrides
    if (args.length === this.interface.deploy.inputs.length + 1) {
      args.pop();
      overrides = last;
    }

    // Make sure the call matches the constructor signature
    logger.checkArgumentCount(args.length, this.interface.deploy.inputs.length, ' in Contract constructor');

    // Resolve ENS names and promises in the arguments
    const params = await resolveAddresses(this.signer, args, this.interface.deploy.inputs);
    params.push(overrides);

    // Get the deployment transaction (with optional overrides)
    const unsignedTx = this.getDeployTransaction(...params);

    // Send the deployment transaction (Here, signer determines if we rely on internal geth signer or external signer)
    let method: (...a: any) => Promise<TransactionResponse>;
    const methodParams: (TransactionRequest | PrivacyOptions)[] = [unsignedTx];

    // Deploy smart contract with different handling based on whether transaction is private and default send transaction method in the signer
    if (privacyOptions.privateFor) {
      // Private contract
      if (this.signer.defaultSendRaw) {
        method = this.signer.sendRawPrivateTransaction;
      } else {
        method = this.signer.sendPrivateTransaction;
      }
      methodParams.push(privacyOptions);
    } else {
      // Public contract
      method = this.signer.sendTransaction;
    }
    const tx: TransactionResponse = await method.apply(this.signer, methodParams);

    const address = getStatic<(tx: TransactionResponse) => string>(this.constructor, 'getContractAddress')(tx);

    const contract = getStatic<
      (address: string, contractInterface: ContractInterface, signer?: Signer) => PrivateContract
    >(this.constructor, 'getContract')(address, this.interface, this.signer);

    defineReadOnly(contract, 'deployTransaction', tx);
    return contract;
  }

  attach(address: string): Contract {
    return (this.constructor as any).getContract(address, this.interface, this.signer);
  }

  connect(signer: PrivateSigner) {
    return new (this.constructor as new (...args: any[]) => PrivateContractFactory)(
      this.interface,
      this.bytecode,
      signer,
    );
  }

  static fromSolidity(compilerOutput: any, signer: PrivateSigner): PrivateContractFactory {
    if (compilerOutput == null) {
      logger.throwError('missing compiler output', Logger.errors.MISSING_ARGUMENT, { argument: 'compilerOutput' });
    }

    if (typeof compilerOutput === 'string') {
      compilerOutput = JSON.parse(compilerOutput);
    }

    const abi = compilerOutput.abi;

    let bytecode: any = null;
    if (compilerOutput.bytecode) {
      bytecode = compilerOutput.bytecode;
    } else if (compilerOutput.evm && compilerOutput.evm.bytecode) {
      bytecode = compilerOutput.evm.bytecode;
    }

    return new this(abi, bytecode, signer);
  }

  static getInterface(contractInterface: ContractInterface) {
    return PrivateContract.getInterface(contractInterface);
  }

  static getContractAddress(tx: { from: string; nonce: BytesLike | BigNumber | number }): string {
    return getContractAddress(tx);
  }

  static getContract(address: string, contractInterface: ContractInterface, signer?: PrivateSigner): PrivateContract {
    return new PrivateContract(address, contractInterface, signer);
  }
}

export class PrivateBaseContract {
  readonly address!: string;
  readonly interface!: Interface;

  readonly signer?: PrivateSigner;
  readonly provider?: PrivateProvider;

  readonly functions!: { [name: string]: ContractFunction };

  readonly callStatic!: { [name: string]: ContractFunction };
  readonly estimateGas!: { [name: string]: ContractFunction<BigNumber> };
  readonly populateTransaction!: {
    [name: string]: ContractFunction<PopulatedTransaction>;
  };

  readonly filters!: { [name: string]: (...args: any[]) => EventFilter };

  // This will always be an address. This will only differ from
  // address if an ENS name was used in the constructor
  readonly resolvedAddress!: Promise<string>;

  // This is only set if the contract was created with a call to deploy
  readonly deployTransaction!: TransactionResponse;

  _deployedPromise!: Promise<PrivateContract>;

  // A list of RunningEvents to track listeners for each event tag
  _runningEvents!: { [eventTag: string]: RunningEvent };

  // Wrapped functions to call emit and allow deregistration from the provider
  _wrappedEmits!: { [eventTag: string]: (...args: any[]) => void };

  constructor(
    addressOrName: string,
    contractInterface: ContractInterface,
    signerOrProvider?: PrivateSigner | PrivateProvider,
  ) {
    // @TODO: Maybe still check the addressOrName looks like a valid address or name?
    // address = getAddress(address);
    defineReadOnly(this, 'interface', getStatic<InterfaceFunc>(new.target, 'getInterface')(contractInterface));

    if (signerOrProvider == null) {
      defineReadOnly(this, 'provider', undefined);
      defineReadOnly(this, 'signer', undefined);
    } else if (Signer.isSigner(signerOrProvider)) {
      defineReadOnly(this, 'provider', signerOrProvider.provider || undefined);
      defineReadOnly(this, 'signer', signerOrProvider);
    } else if (Provider.isProvider(signerOrProvider)) {
      defineReadOnly(this, 'provider', signerOrProvider);
      defineReadOnly(this, 'signer', undefined);
    } else {
      logger.throwArgumentError('invalid signer or provider', 'signerOrProvider', signerOrProvider);
    }

    defineReadOnly(this, 'callStatic', {});
    defineReadOnly(this, 'estimateGas', {});
    defineReadOnly(this, 'functions', {});
    defineReadOnly(this, 'populateTransaction', {});

    defineReadOnly(this, 'filters', {});

    {
      const uniqueFilters: { [name: string]: string[] } = {};
      Object.keys(this.interface.events).forEach((eventSignature) => {
        const event = this.interface.events[eventSignature];
        defineReadOnly(this.filters, eventSignature, (...args: any[]) => {
          return {
            address: this.address,
            topics: this.interface.encodeFilterTopics(event, args),
          };
        });
        if (!uniqueFilters[event.name]) {
          uniqueFilters[event.name] = [];
        }
        uniqueFilters[event.name].push(eventSignature);
      });

      Object.keys(uniqueFilters).forEach((name) => {
        const filters = uniqueFilters[name];
        if (filters.length === 1) {
          defineReadOnly(this.filters, name, this.filters[filters[0]]);
        } else {
          logger.warn(`Duplicate definition of ${name} (${filters.join(', ')})`);
        }
      });
    }

    defineReadOnly(this, '_runningEvents', {});
    defineReadOnly(this, '_wrappedEmits', {});

    if (addressOrName == null) {
      logger.throwArgumentError('invalid contract address or ENS name', 'addressOrName', addressOrName);
    }

    defineReadOnly(this, 'address', addressOrName);
    if (this.provider) {
      defineReadOnly(this, 'resolvedAddress', resolveName(this.provider, addressOrName));
    } else {
      try {
        defineReadOnly(this, 'resolvedAddress', Promise.resolve(getAddress(addressOrName)));
      } catch (error) {
        // Without a provider, we cannot use ENS names
        logger.throwError(
          'provider is required to use ENS name as contract address',
          Logger.errors.UNSUPPORTED_OPERATION,
          {
            operation: 'new Contract',
          },
        );
      }
    }

    // Swallow bad ENS names to prevent Unhandled Exceptions
    this.resolvedAddress.catch((e) => undefined);

    const uniqueNames: { [name: string]: string[] } = {};
    const uniqueSignatures: { [signature: string]: boolean } = {};
    Object.keys(this.interface.functions).forEach((signature) => {
      const fragment = this.interface.functions[signature];

      // Check that the signature is unique; if not the ABI generation has
      // not been cleaned or may be incorrectly generated
      if (uniqueSignatures[signature]) {
        logger.warn(`Duplicate ABI entry for ${JSON.stringify(signature)}`);
        return;
      }
      uniqueSignatures[signature] = true;

      // Track unique names; we only expose bare named functions if they
      // are ambiguous
      {
        const name = fragment.name;
        if (!uniqueNames[`%${name}`]) {
          uniqueNames[`%${name}`] = [];
        }
        uniqueNames[`%${name}`].push(signature);
      }

      if ((this as PrivateContract)[signature] == null) {
        defineReadOnly<any, any>(this, signature, buildDefault(this, fragment, true));
      }

      // We do not collapse simple calls on this bucket, which allows
      // frameworks to safely use this without introspection as well as
      // allows decoding error recovery.
      if (this.functions[signature] == null) {
        defineReadOnly(this.functions, signature, buildDefault(this, fragment, false));
      }

      if (this.callStatic[signature] == null) {
        defineReadOnly(this.callStatic, signature, buildCall(this, fragment, true));
      }

      if (this.populateTransaction[signature] == null) {
        defineReadOnly(this.populateTransaction, signature, buildPopulate(this, fragment));
      }

      if (this.estimateGas[signature] == null) {
        defineReadOnly(this.estimateGas, signature, buildEstimate(this, fragment));
      }
    });

    Object.keys(uniqueNames).forEach((name) => {
      // Ambiguous names to not get attached as bare names
      const signatures = uniqueNames[name];
      if (signatures.length > 1) {
        return;
      }

      // Strip off the leading "%" used for prototype protection
      name = name.substring(1);

      const signature = signatures[0];

      // If overwriting a member property that is null, swallow the error
      try {
        if ((this as PrivateContract)[name] == null) {
          defineReadOnly(this as PrivateContract, name, (this as PrivateContract)[signature]);
        }
      } catch (e) {}

      if (this.functions[name] == null) {
        defineReadOnly(this.functions, name, this.functions[signature]);
      }

      if (this.callStatic[name] == null) {
        defineReadOnly(this.callStatic, name, this.callStatic[signature]);
      }

      if (this.populateTransaction[name] == null) {
        defineReadOnly(this.populateTransaction, name, this.populateTransaction[signature]);
      }

      if (this.estimateGas[name] == null) {
        defineReadOnly(this.estimateGas, name, this.estimateGas[signature]);
      }
    });
  }

  static getContractAddress(transaction: { from: string; nonce: BigNumberish }): string {
    return getContractAddress(transaction);
  }

  static getInterface(contractInterface: ContractInterface): Interface {
    if (Interface.isInterface(contractInterface)) {
      return contractInterface;
    }
    return new Interface(contractInterface);
  }

  // @TODO: Allow timeout?
  deployed(): Promise<PrivateContract> {
    return this._deployed();
  }

  _deployed(blockTag?: BlockTag): Promise<PrivateContract> {
    if (!this._deployedPromise) {
      // If we were just deployed, we know the transaction we should occur in
      if (this.deployTransaction) {
        this._deployedPromise = this.deployTransaction.wait().then(() => {
          return this;
        });
      } else {
        // @TODO: Once we allow a timeout to be passed in, we will wait
        // up to that many blocks for getCode

        // Otherwise, poll for our code to be deployed
        this._deployedPromise = this.provider!.getCode(this.address, blockTag).then((code) => {
          if (code === '0x') {
            logger.throwError('contract not deployed', Logger.errors.UNSUPPORTED_OPERATION, {
              contractAddress: this.address,
              operation: 'getDeployed',
            });
          }
          return this;
        });
      }
    }

    return this._deployedPromise;
  }

  // @TODO:
  // estimateFallback(overrides?: TransactionRequest): Promise<BigNumber>

  // @TODO:
  // estimateDeploy(bytecode: string, ...args): Promise<BigNumber>

  fallback(overrides?: TransactionRequest): Promise<TransactionResponse> {
    if (!this.signer) {
      logger.throwError('sending a transactions require a signer', Logger.errors.UNSUPPORTED_OPERATION, {
        operation: 'sendTransaction(fallback)',
      });
    }

    const tx: Deferrable<TransactionRequest> = shallowCopy(overrides || {});

    ['from', 'to'].forEach((key) => {
      if ((tx as any)[key] == null) {
        return;
      }
      logger.throwError('cannot override ' + key, Logger.errors.UNSUPPORTED_OPERATION, { operation: key });
    });

    tx.to = this.resolvedAddress;
    return this.deployed().then(() => {
      const ptx = tx as PrivateTransactionRequest;
      return this.signer!.sendTransaction(ptx);
    });
  }

  // Reconnect to a different signer or provider
  connect(signerOrProvider: PrivateSigner | PrivateProvider | Signer | Provider | string): PrivateContract {
    if (typeof signerOrProvider === 'string') {
      signerOrProvider = new VoidSigner(signerOrProvider, this.provider);
    }

    const contract = new (this.constructor as new (...args: any[]) => PrivateContract)(
      this.address,
      this.interface,
      signerOrProvider,
    );
    if (this.deployTransaction) {
      defineReadOnly(contract, 'deployTransaction', this.deployTransaction);
    }

    return contract;
  }

  // Re-attach to a different on-chain instance of this contract
  attach(addressOrName: string): PrivateContract {
    return new (this.constructor as new (...args: any[]) => PrivateContract)(
      addressOrName,
      this.interface,
      this.signer || this.provider,
    );
  }

  static isIndexed(value: any): value is Indexed {
    return Indexed.isIndexed(value);
  }

  private _normalizeRunningEvent(runningEvent: RunningEvent): RunningEvent {
    // Already have an instance of this event running; we can re-use it
    if (this._runningEvents[runningEvent.tag]) {
      return this._runningEvents[runningEvent.tag];
    }
    return runningEvent;
  }

  private _getRunningEvent(eventName: EventFilter | string): RunningEvent {
    if (typeof eventName === 'string') {
      // Listen for "error" events (if your contract has an error event, include
      // the full signature to bypass this special event keyword)
      if (eventName === 'error') {
        return this._normalizeRunningEvent(new ErrorRunningEvent());
      }

      // Listen for any event that is registered
      if (eventName === 'event') {
        return this._normalizeRunningEvent(new RunningEvent('event', undefined));
      }

      // Listen for any event
      if (eventName === '*') {
        return this._normalizeRunningEvent(new WildcardRunningEvent(this.address, this.interface));
      }

      // Get the event Fragment (throws if ambiguous/unknown event)
      const fragment = this.interface.getEvent(eventName);
      return this._normalizeRunningEvent(new FragmentRunningEvent(this.address, this.interface, fragment));
    }

    // We have topics to filter by...
    if (eventName.topics && eventName.topics.length > 0) {
      // Is it a known topichash? (throws if no matching topichash)
      try {
        const topic = eventName.topics[0];
        if (typeof topic !== 'string') {
          throw new Error('invalid topic'); // @TODO: May happen for anonymous events
        }
        const fragment = this.interface.getEvent(topic);
        return this._normalizeRunningEvent(
          new FragmentRunningEvent(this.address, this.interface, fragment, eventName.topics),
        );
      } catch (error) {}

      // Filter by the unknown topichash
      const filter: EventFilter = {
        address: this.address,
        topics: eventName.topics,
      };

      return this._normalizeRunningEvent(new RunningEvent(getEventTag(filter), filter));
    }

    return this._normalizeRunningEvent(new WildcardRunningEvent(this.address, this.interface));
  }

  _checkRunningEvents(runningEvent: RunningEvent): void {
    if (runningEvent.listenerCount() === 0) {
      delete this._runningEvents[runningEvent.tag];

      // If we have a poller for this, remove it
      const emit = this._wrappedEmits[runningEvent.tag];
      if (emit && runningEvent.filter) {
        this.provider?.off(runningEvent.filter, emit);
        delete this._wrappedEmits[runningEvent.tag];
      }
    }
  }

  // Subclasses can override this to gracefully recover
  // from parse errors if they wish
  _wrapEvent(runningEvent: RunningEvent, log: Log, listener: Listener | null): Event {
    const event = deepCopy(log) as Event;

    event.removeListener = () => {
      if (!listener) {
        return;
      }
      runningEvent.removeListener(listener);
      this._checkRunningEvents(runningEvent);
    };

    event.getBlock = () => {
      return this.provider!.getBlock(log.blockHash);
    };
    event.getTransaction = () => {
      return this.provider!.getTransaction(log.transactionHash);
    };
    event.getTransactionReceipt = () => {
      return this.provider!.getTransactionReceipt(log.transactionHash);
    };

    // This may throw if the topics and data mismatch the signature
    runningEvent.prepareEvent(event);

    return event;
  }

  private _addEventListener(runningEvent: RunningEvent, listener: Listener, once: boolean): void {
    if (!this.provider) {
      logger.throwError('events require a provider or a signer with a provider', Logger.errors.UNSUPPORTED_OPERATION, {
        operation: 'once',
      });
    }

    runningEvent.addListener(listener, once);

    // Track this running event and its listeners (may already be there; but no hard in updating)
    this._runningEvents[runningEvent.tag] = runningEvent;

    // If we are not polling the provider, start polling
    if (!this._wrappedEmits[runningEvent.tag]) {
      const wrappedEmit = (log: Log) => {
        const event = this._wrapEvent(runningEvent, log, listener);

        // Try to emit the result for the parameterized event...
        if (event.decodeError == null) {
          try {
            const args = runningEvent.getEmit(event);
            this.emit(runningEvent.filter!, ...args);
          } catch (error: any) {
            event.decodeError = error.error;
          }
        }

        // Always emit "event" for fragment-base events
        if (runningEvent.filter != null) {
          this.emit('event', event);
        }

        // Emit "error" if there was an error
        if (event.decodeError != null) {
          this.emit('error', event.decodeError, event);
        }
      };
      this._wrappedEmits[runningEvent.tag] = wrappedEmit;

      // Special events, like "error" do not have a filter
      if (runningEvent.filter != null) {
        this.provider?.on(runningEvent.filter, wrappedEmit);
      }
    }
  }

  queryFilter(
    event: EventFilter | string,
    fromBlockOrBlockhash?: BlockTag | string,
    toBlock?: BlockTag,
  ): Promise<Event[]> {
    const runningEvent = this._getRunningEvent(event);
    const filter = shallowCopy(runningEvent.filter);

    if (typeof fromBlockOrBlockhash === 'string' && isHexString(fromBlockOrBlockhash, 32)) {
      if (toBlock != null) {
        logger.throwArgumentError('cannot specify toBlock with blockhash', 'toBlock', toBlock);
      }
      (filter as FilterByBlockHash).blockHash = fromBlockOrBlockhash;
    } else {
      (filter as Filter).fromBlock = fromBlockOrBlockhash != null ? fromBlockOrBlockhash : 0;
      (filter as Filter).toBlock = toBlock != null ? toBlock : 'latest';
    }

    return this.provider!.getLogs(filter!).then((logs) => {
      return logs.map((log) => this._wrapEvent(runningEvent, log, null));
    });
  }

  on(event: EventFilter | string, listener: Listener): this {
    this._addEventListener(this._getRunningEvent(event), listener, false);
    return this;
  }

  once(event: EventFilter | string, listener: Listener): this {
    this._addEventListener(this._getRunningEvent(event), listener, true);
    return this;
  }

  emit(eventName: EventFilter | string, ...args: any[]): boolean {
    if (!this.provider) {
      return false;
    }

    const runningEvent = this._getRunningEvent(eventName);
    const result = runningEvent.run(args) > 0;

    // May have drained all the "once" events; check for living events
    this._checkRunningEvents(runningEvent);

    return result;
  }

  listenerCount(eventName?: EventFilter | string): number {
    if (!this.provider) {
      return 0;
    }
    if (eventName == null) {
      return Object.keys(this._runningEvents).reduce((accum, key) => {
        return accum + this._runningEvents[key].listenerCount();
      }, 0);
    }
    return this._getRunningEvent(eventName).listenerCount();
  }

  listeners(eventName?: EventFilter | string): Listener[] {
    if (!this.provider) {
      return [];
    }

    if (eventName == null) {
      const result: Listener[] = [];
      for (const tag in this._runningEvents) {
        if (this._runningEvents.hasOwnProperty(tag)) {
          this._runningEvents[tag].listeners().forEach((listener) => {
            result.push(listener);
          });
        }
      }
      return result;
    }

    return this._getRunningEvent(eventName).listeners();
  }

  removeAllListeners(eventName?: EventFilter | string): this {
    if (!this.provider) {
      return this;
    }

    if (eventName == null) {
      for (const tag in this._runningEvents) {
        if (this._runningEvents.hasOwnProperty(tag)) {
          const event = this._runningEvents[tag];
          event.removeAllListeners();
          this._checkRunningEvents(event);
        }
      }
      return this;
    }

    // Delete any listeners
    const runningEvent = this._getRunningEvent(eventName);
    runningEvent.removeAllListeners();
    this._checkRunningEvents(runningEvent);

    return this;
  }

  off(eventName: EventFilter | string, listener: Listener): this {
    if (!this.provider) {
      return this;
    }
    const runningEvent = this._getRunningEvent(eventName);
    runningEvent.removeListener(listener);
    this._checkRunningEvents(runningEvent);
    return this;
  }

  removeListener(eventName: EventFilter | string, listener: Listener): this {
    return this.off(eventName, listener);
  }
}

export class PrivateContract extends PrivateBaseContract {
  // The meta-class properties
  readonly [key: string]: ContractFunction | any;
}

function buildDefault(
  contract: PrivateContract,
  fragment: FunctionFragment,
  collapseSimple: boolean,
): ContractFunction {
  if (fragment.constant) {
    return buildCall(contract, fragment, collapseSimple);
  }
  return buildSend(contract, fragment);
}

function buildCall(contract: PrivateContract, fragment: FunctionFragment, collapseSimple: boolean): ContractFunction {
  const signerOrProvider = contract.signer || contract.provider;

  return async (...args: any[]): Promise<any> => {
    // Extract the "blockTag" override if present
    let blockTag;
    if (args.length === fragment.inputs.length + 1 && typeof args[args.length - 1] === 'object') {
      const overrides = shallowCopy(args.pop());
      if (overrides.blockTag != null) {
        blockTag = await overrides.blockTag;
      }
      delete overrides.blockTag;
      args.push(overrides);
    }

    // If the contract was just deployed, wait until it is mined
    if (contract.deployTransaction != null) {
      await contract._deployed(blockTag);
    }

    // Call a node and get the result
    const tx = await populateTransaction(contract, fragment, args);
    const result = await signerOrProvider!.call(tx, blockTag);

    try {
      let value = contract.interface.decodeFunctionResult(fragment, result);
      if (collapseSimple && fragment?.outputs?.length === 1) {
        value = value[0];
      }
      return value;
    } catch (error: any) {
      if (error.code === Logger.errors.CALL_EXCEPTION) {
        error.address = contract.address;
        error.args = args;
        error.transaction = tx;
      }
      throw error;
    }
  };
}

function buildEstimate(contract: PrivateContract, fragment: FunctionFragment): ContractFunction<BigNumber> {
  const signerOrProvider = contract.signer || contract.provider;
  return async (...args: any[]): Promise<BigNumber> => {
    if (!signerOrProvider) {
      logger.throwError('estimate require a provider or signer', Logger.errors.UNSUPPORTED_OPERATION, {
        operation: 'estimateGas',
      });
    }

    const tx = await populateTransaction(contract, fragment, args);
    return await signerOrProvider!.estimateGas(tx);
  };
}

function buildPopulate(contract: PrivateContract, fragment: FunctionFragment): ContractFunction<PopulatedTransaction> {
  return (...args: any[]): Promise<PopulatedTransaction> => {
    return populateTransaction(contract, fragment, args);
  };
}

function buildSend(contract: PrivateContract, fragment: FunctionFragment): ContractFunction<TransactionResponse> {
  return async (...args: any[]): Promise<TransactionResponse> => {
    if (!contract.signer) {
      logger.throwError('sending a transaction requires a signer', Logger.errors.UNSUPPORTED_OPERATION, {
        operation: 'sendTransaction',
      });
    }

    // If the contract was just deployed, wait until it is mined
    if (contract.deployTransaction != null) {
      await contract._deployed();
    }

    const privateSigner = contract.signer as PrivateSigner;
    const privacyOptions: any = {};
    let last: any;
    if (args.length > 0 && args.slice(-1)) {
      last = args[args.length - 1];
      if (typeof last === 'object' && 'privateFor' in last) {
        last = { ...last };
        privacyOptions.privateFor = last.privateFor;
        delete last.privateFor;
        if ('privacyFlag' in last) {
          privacyOptions.privacyFlag = last.privacyFlag;
          delete last.privacyFlag;
        }
      }
    }

    const txRequest = await populateTransaction(contract, fragment, args);

    let method: (...a: any) => Promise<TransactionResponse>;
    const methodParams = [txRequest];
    if (privacyOptions.privateFor) {
      // Private contract
      if (privateSigner.defaultSendRaw) {
        method = privateSigner.sendRawPrivateTransaction;
      } else {
        method = privateSigner.sendPrivateTransaction;
      }
      methodParams.push(privacyOptions);
    } else {
      // Public contract
      method = privateSigner.sendTransaction;
    }
    const tx = await method.apply(privateSigner, methodParams);

    // Tweak the tx.wait so the receipt has extra properties
    addContractWait(contract, tx);

    return tx;
  };
}

async function populateTransaction(
  contract: PrivateContract,
  fragment: FunctionFragment,
  args: any[],
): Promise<PopulatedTransaction> {
  // If an extra argument is given, it is overrides
  let overrides: CallOverrides2 = {};
  if (args.length === fragment.inputs.length + 1 && typeof args[args.length - 1] === 'object') {
    overrides = shallowCopy(args.pop());
  }

  // Make sure the parameter count matches
  logger.checkArgumentCount(args.length, fragment.inputs.length, 'passed to contract');

  // Populate "from" override (allow promises)
  if (contract.signer) {
    if (overrides.from) {
      // Contracts with a Signer are from the Signer's frame-of-reference;
      // but we allow overriding "from" if it matches the signer
      overrides.from = resolveProperties({
        override: resolveName(contract.signer, overrides.from),
        signer: contract.signer.getAddress(),
      }).then(async (check) => {
        if (getAddress(check.signer) !== check.override) {
          logger.throwError('Contract with a Signer cannot override from', Logger.errors.UNSUPPORTED_OPERATION, {
            operation: 'overrides.from',
          });
        }

        return check.override;
      });
    } else {
      overrides.from = contract.signer.getAddress();
    }
  } else if (overrides.from) {
    overrides.from = resolveName(contract.provider!, overrides.from);
  }

  // Wait for all dependencies to be resolved (prefer the signer over the provider)
  const resolved = await resolveProperties({
    args: resolveAddresses(contract.signer || contract.provider!, args, fragment.inputs),
    address: contract.resolvedAddress,
    overrides: resolveProperties(overrides) || {},
  });

  // The ABI coded transaction
  const data = contract.interface.encodeFunctionData(fragment, resolved.args);
  const tx: PopulatedTransaction = {
    data,
    to: resolved.address,
  };

  // Resolved Overrides
  const ro = resolved.overrides;

  // Populate simple overrides
  if (ro.nonce != null) {
    tx.nonce = BigNumber.from(ro.nonce).toNumber();
  }
  if (ro.gasLimit != null) {
    tx.gasLimit = BigNumber.from(ro.gasLimit);
  }
  if (ro.gasPrice != null) {
    tx.gasPrice = BigNumber.from(ro.gasPrice);
  }
  if (ro.maxFeePerGas != null) {
    tx.maxFeePerGas = BigNumber.from(ro.maxFeePerGas);
  }
  if (ro.maxPriorityFeePerGas != null) {
    tx.maxPriorityFeePerGas = BigNumber.from(ro.maxPriorityFeePerGas);
  }
  if (ro.from != null) {
    tx.from = ro.from;
  }

  if (ro.type != null) {
    tx.type = ro.type;
  }
  if (ro.accessList != null) {
    tx.accessList = accessListify(ro.accessList);
  }

  // If there was no "gasLimit" override, but the ABI specifies a default, use it
  if (tx.gasLimit == null && fragment.gas != null) {
    // Compute the intrinsic gas cost for this transaction
    // @TODO: This is based on the yellow paper as of Petersburg; this is something
    // we may wish to parameterize in v6 as part of the Network object. Since this
    // is always a non-nil to address, we can ignore G_create, but may wish to add
    // similar logic to the ContractFactory.
    let intrinsic = 21000;
    const bytes = arrayify(data);
    for (const i of Array(bytes.length).keys()) {
      intrinsic += 4;
      if (bytes[i]) {
        intrinsic += 64;
      }
    }
    tx.gasLimit = BigNumber.from(fragment.gas).add(intrinsic);
  }

  // Populate "value" override
  if (ro.value) {
    const roValue = BigNumber.from(ro.value);
    if (!roValue.isZero() && !fragment.payable) {
      logger.throwError('non-payable method cannot override value', Logger.errors.UNSUPPORTED_OPERATION, {
        operation: 'overrides.value',
        value: overrides.value,
      });
    }
    tx.value = roValue;
  }

  if (ro.customData) {
    tx.customData = shallowCopy(ro.customData);
  }

  if (ro.ccipReadEnabled) {
    tx.ccipReadEnabled = !!ro.ccipReadEnabled;
  }

  // Remove the overrides
  delete overrides.nonce;
  delete overrides.gasLimit;
  delete overrides.gasPrice;
  delete overrides.from;
  delete overrides.value;

  delete overrides.type;
  delete overrides.accessList;

  delete overrides.maxFeePerGas;
  delete overrides.maxPriorityFeePerGas;

  delete overrides.customData;
  delete overrides.ccipReadEnabled;

  delete overrides.privateFor;
  delete overrides.privacyFlag;

  // Make sure there are no stray overrides, which may indicate a
  // typo or using an unsupported key.
  const leftovers = Object.keys(overrides).filter((key) => (overrides as any)[key] != null);
  if (leftovers.length) {
    logger.throwError(
      `cannot override ${leftovers.map((l) => JSON.stringify(l)).join(',')}`,
      Logger.errors.UNSUPPORTED_OPERATION,
      {
        operation: 'overrides',
        overrides: leftovers,
      },
    );
  }

  return tx;
}

function addContractWait(contract: PrivateContract, tx: TransactionResponse) {
  const wait = tx.wait.bind(tx);
  tx.wait = (confirmations?: number) => {
    return wait(confirmations).then((receipt: ContractReceipt) => {
      receipt.events = receipt.logs.map((log) => {
        const event: Event = deepCopy(log) as Event;
        let parsed: LogDescription | null = null;
        try {
          parsed = contract.interface.parseLog(log);
        } catch (e) {}

        // Successfully parsed the event log; include it
        if (parsed) {
          event.args = parsed.args;
          event.decode = (data: BytesLike, topics?: any[]) => {
            return contract.interface.decodeEventLog(parsed!.eventFragment, data, topics);
          };
          event.event = parsed.name;
          event.eventSignature = parsed.signature;
        }

        // Useful operations
        event.removeListener = () => {
          return contract.provider;
        };
        event.getBlock = () => {
          return contract.provider!.getBlock(receipt.blockHash);
        };
        event.getTransaction = () => {
          return contract.provider!.getTransaction(receipt.transactionHash);
        };
        event.getTransactionReceipt = () => {
          return Promise.resolve(receipt);
        };

        return event;
      });

      return receipt;
    });
  };
}

async function resolveName(resolver: Signer | Provider, nameOrPromise: string | Promise<string>): Promise<string> {
  const name = await nameOrPromise;

  if (typeof name !== 'string') {
    logger.throwArgumentError('invalid address or ENS name', 'name', name);
  }

  // If it is already an address, just use it (after adding checksum)
  try {
    return getAddress(name);
  } catch (error) {}

  if (!resolver) {
    logger.throwError('a provider or signer is needed to resolve ENS names', Logger.errors.UNSUPPORTED_OPERATION, {
      operation: 'resolveName',
    });
  }

  const address = await resolver.resolveName(name);

  if (address == null) {
    logger.throwArgumentError('resolver or addr is not configured for ENS name', 'name', name);
  }

  return address!;
}

// Recursively replaces ENS names with promises to resolve the name and resolves all properties
async function resolveAddresses(
  resolver: Signer | Provider,
  value: any,
  paramType: ParamType | ParamType[],
): Promise<any> {
  if (Array.isArray(paramType)) {
    return await Promise.all(
      paramType.map((type, index) => {
        return resolveAddresses(resolver, Array.isArray(value) ? value[index] : value[type.name], type);
      }),
    );
  }

  if (paramType.type === 'address') {
    return await resolver.resolveName(value);
  }

  if (paramType.type === 'tuple') {
    return await resolveAddresses(resolver, value, paramType.components);
  }

  if (paramType.baseType === 'array') {
    if (!Array.isArray(value)) {
      return Promise.reject(
        logger.makeError('invalid value for array', Logger.errors.INVALID_ARGUMENT, {
          argument: 'value',
          value,
        }),
      );
    }
    return await Promise.all(value.map((v) => resolveAddresses(resolver, v, paramType.arrayChildren)));
  }

  return value;
}
class RunningEvent {
  readonly tag!: string;
  readonly filter?: EventFilter;
  private _listeners: { listener: Listener; once: boolean }[];

  constructor(tag: string, filter: EventFilter | undefined) {
    defineReadOnly(this, 'tag', tag);
    defineReadOnly(this, 'filter', filter);
    this._listeners = [];
  }

  addListener(listener: Listener, once: boolean): void {
    this._listeners.push({ listener, once });
  }

  removeListener(listener: Listener): void {
    let done = false;
    this._listeners = this._listeners.filter((item) => {
      if (done || item.listener !== listener) {
        return true;
      }
      done = true;
      return false;
    });
  }

  removeAllListeners(): void {
    this._listeners = [];
  }

  listeners(): Listener[] {
    return this._listeners.map((i) => i.listener);
  }

  listenerCount(): number {
    return this._listeners.length;
  }

  run(args: any[]): number {
    const listenerCount = this.listenerCount();
    this._listeners = this._listeners.filter((item) => {
      const argsCopy = args.slice();

      // Call the callback in the next event loop
      setTimeout(() => {
        item.listener.apply(this, argsCopy);
      }, 0);

      // Reschedule it if it not "once"
      return !item.once;
    });

    return listenerCount;
  }

  prepareEvent(event: Event): void {}

  // Returns the array that will be applied to an emit
  getEmit(event: Event): any[] {
    return [event];
  }
}

class ErrorRunningEvent extends RunningEvent {
  constructor() {
    super('error', undefined);
  }
}

// @TODO Fragment should inherit Wildcard? and just override getEmit?
//       or have a common abstract super class, with enough constructor
//       options to configure both.

// A Fragment Event will populate all the properties that Wildcard
// will, and additionally dereference the arguments when emitting
class FragmentRunningEvent extends RunningEvent {
  readonly address?: string;
  readonly interface!: Interface;
  readonly fragment!: EventFragment;

  constructor(address: string, contractInterface: Interface, fragment: EventFragment, topics?: (string | string[])[]) {
    const filter: EventFilter = {
      address,
    };

    const topic = contractInterface.getEventTopic(fragment);
    if (topics) {
      if (topic !== topics[0]) {
        logger.throwArgumentError('topic mismatch', 'topics', topics);
      }
      filter.topics = topics.slice();
    } else {
      filter.topics = [topic];
    }

    super(getEventTag(filter), filter);
    defineReadOnly(this, 'address', address);
    defineReadOnly(this, 'interface', contractInterface);
    defineReadOnly(this, 'fragment', fragment);
  }

  prepareEvent(event: Event): void {
    super.prepareEvent(event);

    event.event = this.fragment.name;
    event.eventSignature = this.fragment.format();

    event.decode = (data: BytesLike, topics?: string[]) => {
      return this.interface.decodeEventLog(this.fragment, data, topics);
    };

    try {
      event.args = this.interface.decodeEventLog(this.fragment, event.data, event.topics);
    } catch (error) {
      event.args = undefined;
      event.decodeError = error as Error;
    }
  }

  getEmit(event: Event): any[] {
    const errors = checkResultErrors(event.args!);
    if (errors.length) {
      throw errors[0].error;
    }

    const args = (event.args || []).slice();
    args.push(event);
    return args;
  }
}

// A Wildcard Event will attempt to populate:
//  - event            The name of the event name
//  - eventSignature   The full signature of the event
//  - decode           A function to decode data and topics
//  - args             The decoded data and topics
class WildcardRunningEvent extends RunningEvent {
  readonly address?: string;
  readonly interface!: Interface;

  constructor(address: string, contractInterface: Interface) {
    super('*', { address });
    defineReadOnly(this, 'address', address);
    defineReadOnly(this, 'interface', contractInterface);
  }

  prepareEvent(event: Event): void {
    super.prepareEvent(event);

    try {
      const parsed = this.interface.parseLog(event);
      event.event = parsed.name;
      event.eventSignature = parsed.signature;

      event.decode = (data: BytesLike, topics?: string[]) => {
        return this.interface.decodeEventLog(parsed.eventFragment, data, topics);
      };

      event.args = parsed.args;
    } catch (error) {
      // No matching event
    }
  }
}

function getEventTag(filter: EventFilter): string {
  if (filter.address && (filter.topics == null || filter.topics.length === 0)) {
    return '*';
  }

  return (
    (filter.address || '*') +
    '@' +
    (filter.topics
      ? filter.topics
          .map((topic) => {
            if (Array.isArray(topic)) {
              return topic.join('|');
            }
            return topic;
          })
          .join(':')
      : '')
  );
}
