Ethers Quorum
==================

[![npm (tag)](https://img.shields.io/npm/v/ethers-quorum)](https://www.npmjs.com/package/ethers-quorum)

Complete Ethereum library and wallet implementation in JavaScript, with support for Quorum


**Features:**

- Interact with [Quorum](https://github.com/ConsenSys/quorum) blockchain
- Interact with external signer
- Specify `privateFor` and `privacyFlag` for transactions

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
  const wallet = new PrivateWallet(process.env.pk, provider);
  const contract = new PrivateContractFactory(obj.abi, obj.bytecode, wallet);
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