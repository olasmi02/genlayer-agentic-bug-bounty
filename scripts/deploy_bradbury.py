import os
import sys
import json
import time
from datetime import datetime, timezone
from eth_account import Account
from genlayer_py import create_account, create_client, chains

def main():
    private_key = os.getenv("GENLAYER_PRIVATE_KEY")
    if private_key:
        account = Account.from_key(private_key)
        print(f"Loaded existing account from GENLAYER_PRIVATE_KEY: {account.address}")
    else:
        # Check if we have a saved deployer key locally
        key_file = "bradbury_deployer_key.json"
        if os.path.exists(key_file):
            with open(key_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
                account = Account.from_key(saved["private_key"])
                print(f"Loaded saved deployer account: {account.address}")
        else:
            account = create_account()
            # Save key locally for convenience
            with open(key_file, "w", encoding="utf-8") as f:
                json.dump({
                    "address": account.address,
                    "private_key": account.key.hex()
                }, f, indent=2)
            print(f"Generated new deployer account: {account.address}")
            print(f"Saved key to {key_file} (keep this safe!).")

    client = create_client(chain=chains.testnet_bradbury, account=account)
    
    # Check balance
    try:
        balance = client.get_balance(account.address)
        print(f"Account Balance on Bradbury: {balance} wei ({balance / 10**18:.6f} GEN)")
    except Exception as e:
        print(f"Warning: Could not fetch balance directly: {e}")
        balance = 0

    if balance == 0:
        print("\n" + "!" * 70)
        print(f"ACTION REQUIRED: Insufficient funds for deployment on Bradbury Testnet.")
        print(f"Deployer Address: {account.address}")
        print("Please fund this address with testnet GEN from the GenLayer Faucet / Discord faucet.")
        print("Once funded, re-run this script to complete deployment.")
        print("!" * 70 + "\n")
        sys.exit(1)

    with open("contracts/AgenticBugBounty.py", "r", encoding="utf-8") as f:
        code = f.read()

    print(f"\nDeploying AgenticBugBounty to GenLayer Bradbury Testnet (Chain ID 4221)...")
    deploy_start_time = datetime.now(timezone.utc)
    print(f"Start Time (UTC): {deploy_start_time.isoformat()}")

    tx_hash = client.deploy_contract(
        code=code,
        args=[account.address],
    )
    print(f"Deployment Transaction Hash: {tx_hash}")
    print(f"Tx Explorer: https://explorer-bradbury.genlayer.com/tx/{tx_hash}")

    print("Waiting for consensus finalization (validators agreeing on deployment)...", flush=True)
    receipt = client.wait_for_transaction_receipt(tx_hash, status="FINALIZED")
    print("Consensus reached! Status:", receipt.get("status_name", receipt.get("status")), flush=True)
    print("Consensus result:", receipt.get("result_name"), flush=True)

    contract_address = (
        receipt.get("contract_address")
        or receipt.get("recipient_address")
        or (receipt.get("data", {}).get("contract_address") if isinstance(receipt.get("data"), dict) else None)
    )

    if not contract_address:
        tx = client.get_transaction(tx_hash)
        contract_address = tx.get("contract_address") or tx.get("recipient_address")

    print("\n" + "=" * 70)
    print("SUCCESS! CONTRACT DEPLOYED ON GENLAYER BRADBURY TESTNET:")
    print(f"Contract Address: {contract_address}")
    print(f"Contract Explorer URL: https://explorer-bradbury.genlayer.com/contracts/{contract_address}")
    print(f"Deployment Tx Hash:    {tx_hash}")
    print(f"Tx Explorer URL:       https://explorer-bradbury.genlayer.com/tx/{tx_hash}")
    print("=" * 70 + "\n")

    meta = {
        "network": "GenLayer Bradbury Testnet",
        "chain_id": 4221,
        "contract_address": contract_address,
        "contract_explorer_url": f"https://explorer-bradbury.genlayer.com/contracts/{contract_address}",
        "address_explorer_url": f"https://explorer-bradbury.genlayer.com/address/{contract_address}",
        "tx_hash": tx_hash,
        "tx_explorer_url": f"https://explorer-bradbury.genlayer.com/tx/{tx_hash}",
        "deployer": account.address,
        "deployed_at": datetime.now(timezone.utc).isoformat(),
    }
    with open("deployment_bradbury.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print("Saved deployment details to deployment_bradbury.json.")

if __name__ == "__main__":
    main()
