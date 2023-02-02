Ethers Quorum
==================

[![npm (tag)](https://img.shields.io/npm/v/ethers-quorum)](https://www.npmjs.com/package/ethers-quorum)

Complete Ethereum library and wallet implementation in JavaScript, with support for Quorum


**Features:**

- Interact with [Quorum](https://github.com/ConsenSys/quorum) blockchain
- Interact with external signer outside geth
- Interact with internal signer within geth
- Specify `privateFor` and `privacyFlag` for private transactions
- Don't pass in `privateFor` for public transactions
- Don't pass in signer URL into `getPrivateSigner` to fallback to unlocked geth keys

| Type  | Private Txn | Public Txn |
| ------------- | ------------- | ------------- |
| External Signer  | &#9745;  | &#9745;  |
| Geth Unlocked Keys | &#9745; | &#9745; |

Installing
----------
**node.js**

```
/home/user/some_project> npm install --save ethers-quorum
```

Examples
----------
**Deploy private contract:**
```javascript
import {
  PrivateJsonRpcProvider,
  PrivateWallet,
  PrivateContractFactory,
} from "ethers-quorum";
import { getAbiBytecode } from "./loader.js";
import * as dotenv from "dotenv";

async function main() {
  dotenv.config();
  const obj = await getAbiBytecode(
    "contracts/SimpleStorage_sol_Storage.abi",
    "contracts/SimpleStorage_sol_Storage.bin"
  );
  const provider = new PrivateJsonRpcProvider(
    process.env.url,
    parseInt(process.env.network),
    process.env.tesseraUrl
  );
  const signer = new PrivateWallet(process.env.pk, provider);
  // const signer = provider.getPrivateSigner('0xf0E2Db6C8dC6c681bB5D6aD121A107f300e9B2b5', 'http://localhost:8630'); // alternative way to use external signer or unlocked geth keys
  // signer.setDefaultSendRaw(false); // set to false use unlocked geth keys instead of external signer
  const contract = new PrivateContractFactory(obj.abi, obj.bytecode, signer);
  const contractInstance = await contract.deploy({
    privateFor: ["BULeR8JyUWhiuuCMU/HLA0Q5pzkYT+cHII3ZKBey3Bo="],
  });
  console.log("Contract", contractInstance);
  console.log("Contract address ::", contractInstance.address);
  console.log("Deployed transaction ::", contractInstance.deployTransaction);
}

main();
```

**Interact with private contract via encoded data:**
```javascript
  const iface = new ethers.utils.Interface(abi);
  const data = iface.encodeFunctionData("store", [25]);
  const resp = await signer.sendTransaction({
    to: contract.address,
    gasLimit: 100_000,
    data,
    privateFor: ["BULeR8JyUWhiuuCMU/HLA0Q5pzkYT+cHII3ZKBey3Bo="],
  });
  console.log("Submitted txn :: ", resp);
  await new Promise((r) => setTimeout(r, 4000)); // wait for txn to populate
  console.log(await contract.retrieve());
```

**Interact with private contract via contract method:**
```javascript
  const resp2 = await contract.store(35, {
    gasLimit: 100_000,
    privateFor: ["BULeR8JyUWhiuuCMU/HLA0Q5pzkYT+cHII3ZKBey3Bo="],
  });
  console.log("Submitted txn :: ", resp2);
  await new Promise((r) => setTimeout(r, 4000)); // wait for txn to populate
  console.log(await contract.retrieve());
```


License
-------

MIT License (including **all** dependencies).