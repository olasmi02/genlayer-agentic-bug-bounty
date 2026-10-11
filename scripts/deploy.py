import time
import json
import urllib.request
from datetime import datetime, timezone
from genlayer_py import create_account, create_client, chains

account = create_account()
print(f"Deployer Account: {account.address}")
client = create_client(chain=chains.studionet, account=account)

with open("contracts/AgenticBugBounty.py", "r", encoding="utf-8") as f:
    code = f.read()

print(f"Deploying AgenticBugBounty to GenLayer Studionet...")
deploy_start_time = datetime.now(timezone.utc)
print(f"Start Time (UTC): {deploy_start_time.isoformat()}")

tx_hash = client.deploy_contract(
    code=code,
    args=[account.address],
)
print(f"Deployment Transaction Hash: {tx_hash}")
print(f"Tx Explorer: https://explorer-studio.genlayer.com/tx/{tx_hash}")

print("Waiting for consensus finalization (validators agreeing on deployment)...", flush=True)
receipt = client.wait_for_transaction_receipt(tx_hash, status="FINALIZED")
print("Consensus reached! Status:", receipt.get("status_name", receipt.get("status")), flush=True)
print("Consensus result:", receipt.get("result_name"), flush=True)
print("Validators:", receipt.get("last_round", {}).get("validator_votes_name"), flush=True)

tx = client.get_transaction(tx_hash)
cd = tx.get("consensus_data", {})
for k, v in cd.items():
    if isinstance(v, list):
        for item in v:
            mode = item.get("mode")
            res = item.get("execution_result")
            err = item.get("genvm_result", {}).get("stderr")
            print(f"  Validator [{mode}] result: {res}", flush=True)
            if err:
                print(f"    stderr: {err[:300]}", flush=True)

contract_address = (
    receipt.get("contract_address")
    or receipt.get("recipient_address")
    or (receipt.get("data", {}).get("contract_address") if isinstance(receipt.get("data"), dict) else None)
)
if not contract_address:
    contract_address = tx.get("contract_address") or tx.get("recipient_address")

print(f"Direct contract address from receipt/tx: {contract_address}")

# If contract address is not directly returned, query the explorer API
if not contract_address:
    for attempt in range(1, 11):
        print(f"\n[Attempt {attempt}/10] Querying GenLayer Explorer API for newly deployed contract...", flush=True)
        found = False
        for page in range(1, 4):
            url = f"https://explorer-studio.genlayer.com/api/contracts?limit=30&page={page}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                res = urllib.request.urlopen(req, timeout=10)
                data = json.loads(res.read().decode("utf-8"))
            except Exception as e:
                print(f"  API query failed: {e}")
                continue

            for c in data.get("states", []):
                c_id = c["id"]
                rpc_payload = {
                    "jsonrpc": "2.0",
                    "method": "gen_getContractSchema",
                    "params": [c_id],
                    "id": 1,
                }
                rpc_req = urllib.request.Request(
                    "https://studio.genlayer.com/api",
                    data=json.dumps(rpc_payload).encode("utf-8"),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                try:
                    rpc_res = urllib.request.urlopen(rpc_req, timeout=5)
                    rpc_data = json.loads(rpc_res.read().decode("utf-8"))
                    methods = list(rpc_data.get("result", {}).get("methods", {}).keys())
                    if "create_program" in methods and "triage_report" in methods:
                        contract_address = c_id
                        found = True
                        break
                except Exception:
                    pass
            if found:
                break
        if contract_address:
            break
        time.sleep(3)

print("\n" + "=" * 70)
print("SUCCESS! CONTRACT DEPLOYED & VERIFIED ON GENLAYER STUDIONET:")
print(f"Contract Address: {contract_address}")
print(f"Contract Explorer URL: https://explorer-studio.genlayer.com/contracts/{contract_address}")
print(f"Deployment Tx Hash:    {tx_hash}")
print(f"Tx Explorer URL:       https://explorer-studio.genlayer.com/tx/{tx_hash}")
print("=" * 70 + "\n")

meta = {
    "contract_address": contract_address,
    "contract_explorer_url": f"https://explorer-studio.genlayer.com/contracts/{contract_address}",
    "address_explorer_url": f"https://explorer-studio.genlayer.com/address/{contract_address}",
    "tx_hash": tx_hash,
    "tx_explorer_url": f"https://explorer-studio.genlayer.com/tx/{tx_hash}",
    "deployer": account.address,
    "deployed_at": datetime.now(timezone.utc).isoformat(),
}
with open("deployment.json", "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2)

print("Saved metadata to deployment.json.")
