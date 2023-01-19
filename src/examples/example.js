const ethers = require('../../lib/index.js'); // npm run build to generate source code
const { getAbiBytecode } = require('./utilities/loader.js');

const main = async () => {
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
  const contractInstance = await contract.deploy({
    privateFor: ['BULeR8JyUWhiuuCMU/HLA0Q5pzkYT+cHII3ZKBey3Bo='],
    privacyFlag: 1,
  });
  console.log('Contract', contractInstance);
  console.log('Contract address ::', contractInstance.address);
  console.log('Deployed transaction ::', contractInstance.deployTransaction);
};

main();
