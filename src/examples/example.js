// Run this script in the same directory

const ethers = require('../../lib/index.js'); // npm run build to generate source code
const { getAbiBytecode } = require('./utilities/loader.js');

const main = async () => {
  const contractInstance = await deploy();
  await interactViaContractMethod(contractInstance);
};

const deploy = async () => {
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
  await contractInstance.store(35, {
    gasLimit: 100_000_000,
    privateFor: ['BULeR8JyUWhiuuCMU/HLA0Q5pzkYT+cHII3ZKBey3Bo='],
    privacyFlag: 1,
  });
  await new Promise((r) => setTimeout(r, 4000)); // wait for txn to populate
  console.log(`Stored value :: ${await contractInstance.retrieve()}`);
};

main();
