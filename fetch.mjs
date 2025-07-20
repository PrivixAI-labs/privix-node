const RPC_URL = 'http://127.0.0.1:8545';
const AUTH_TOKEN = ''; // Replace with your token

async function getBlockNumber() {
  const payload = {
    jsonrpc: "2.0",
    method: "eth_blockNumber",
    params: [],
    id: 1
  };

  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${AUTH_TOKEN}`
    },
    body: JSON.stringify(payload)
  });

  // Check if response is JSON
  const text = await res.text();
  try {
    const data = JSON.parse(text);
    const blockNumber = parseInt(data.result, 16);
    console.log("Latest block number:", blockNumber);
  } catch (err) {
    console.error("Failed to parse JSON:", text);
  }
}

getBlockNumber();
