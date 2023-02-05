// Run this script in the same directory - node example.js

const ethers = require('../../lib/index.js'); // npm run build to generate source code
const { getAbiBytecode } = require('./utilities/loader.js');

/**
 * Deploy and interact with private contracts via Private Signer/Wallet
 */
const main = async () => {
  // const contractInstance = await deploy_with_private_signer(); // implementation can be switched between deploy_with_private_signer() and deploy_with_private_wallet()
  const contractInstance = await deploy_with_private_wallet();
  await interactViaContractMethod(contractInstance);
};

/**
 * Use private wallet when passing in private keys directly into the instance
 * @returns {ethers.PrivateContract}
 */
const deploy_with_private_wallet = async () => {
  const obj = await getAbiBytecode(
    'contracts/SimpleStorage_sol_Storage.abi',
    'contracts/SimpleStorage_sol_Storage.bin',
  );
  const provider = new ethers.PrivateJsonRpcProvider('http://localhost:20000', 1337, 'http://localhost:9081'); // quorum, chainID, tessera
  const wallet = new ethers.PrivateWallet(
    '0x8bbbb1b345af56b560a5b20bd4b0ed1cd8cc9958a16262bc75118453cb546df7',
    provider,
  ); // don't use this in a production env
  const contract = new ethers.PrivateContractFactory(obj.abi, obj.bytecode, wallet);
  const txnOps = {
    gasLimit: 100_000_000,
    privateFor: ['BULeR8JyUWhiuuCMU/HLA0Q5pzkYT+cHII3ZKBey3Bo='],
    privacyFlag: 1,
  };
  const contractInstance = await contract.deploy(txnOps);
  console.log('Contract', contractInstance);
  console.log('Contract address ::', contractInstance.address);
  console.log('Deployed transaction ::', contractInstance.deployTransaction);

  return contractInstance;
};

/**
 * Use private signer when either using external signer or unlocked account keys within geth
 * @param {boolean} setDefaultSendRaw
 * @returns {ethers.PrivateContract}
 */
const deploy_with_private_signer = async (setDefaultSendRaw = false) => {
  const obj = await getAbiBytecode(
    'contracts/SimpleStorage_sol_Storage.abi',
    'contracts/SimpleStorage_sol_Storage.bin',
  );
  const provider = new ethers.PrivateJsonRpcProvider('http://localhost:20000', 1337, 'http://localhost:9081'); // quorum, chainID, tessera
  const signer = provider.getPrivateSigner('0xf0E2Db6C8dC6c681bB5D6aD121A107f300e9B2b5', 'http://localhost:8630');
  signer.setDefaultSendRaw(setDefaultSendRaw); // set to false use unlocked geth keys
  const contract = new ethers.PrivateContractFactory(obj.abi, obj.bytecode, signer);
  const txnOps = {
    gasLimit: 100_000_000,
    privateFor: ['BULeR8JyUWhiuuCMU/HLA0Q5pzkYT+cHII3ZKBey3Bo='],
    privacyFlag: 1,
  };
  const contractInstance = await contract.deploy(txnOps);
  console.log('Contract', contractInstance);
  console.log('Contract address ::', contractInstance.address);
  console.log('Deployed transaction ::', contractInstance.deployTransaction);

  return contractInstance;
};

const interactViaContractMethod = async (contractInstance) => {
  console.log('Storing value in simple storage contract');
  const resp = await contractInstance.store(35, {
    gasLimit: 100_000_000,
    privateFor: ['BULeR8JyUWhiuuCMU/HLA0Q5pzkYT+cHII3ZKBey3Bo='],
    privacyFlag: 1,
  });
  await resp.wait();
  console.log(`Stored value :: ${await contractInstance.retrieve()}`);
};

main();
