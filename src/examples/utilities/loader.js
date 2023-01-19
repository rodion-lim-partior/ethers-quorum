const fs = require('fs');

const getAbiBytecode = (abiPath, bytecodePath) => {
  const bytecode = fs.readFileSync(bytecodePath).toString();
  const abi = fs.readFileSync(abiPath).toString();
  return {
    abi,
    bytecode,
  };
};

module.exports = { getAbiBytecode };
