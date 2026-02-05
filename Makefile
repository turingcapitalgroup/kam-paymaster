# KAM Paymaster Deployment Makefile
# Usage: make deploy-mainnet, make deploy-sepolia, make deploy-localhost
-include .env
export

.PHONY: help deploy-mainnet deploy-mainnet-dry-run deploy-sepolia deploy-sepolia-dry-run deploy-localhost deploy-localhost-dry-run verify-mainnet verify-sepolia verify clean clean-all format-output test build compile

# Default target
help:
	@echo "KAM Paymaster Deployment Commands"
	@echo "=================================="
	@echo ""
	@echo "Deploy contracts:"
	@echo "make deploy-mainnet          - Deploy to mainnet"
	@echo "make deploy-mainnet-dry-run  - Simulate deployment to mainnet (no broadcast)"
	@echo "make deploy-sepolia          - Deploy to Sepolia testnet"
	@echo "make deploy-sepolia-dry-run  - Simulate deployment to Sepolia (no broadcast)"
	@echo "make deploy-localhost        - Deploy to localhost"
	@echo "make deploy-localhost-dry-run- Simulate deployment to localhost (no broadcast)"
	@echo ""
	@echo "Verify contracts on Etherscan:"
	@echo "make verify-mainnet          - Verify contracts on mainnet Etherscan"
	@echo "make verify-sepolia          - Verify contracts on Sepolia Etherscan"
	@echo ""
	@echo "Other commands:"
	@echo "make verify             - Check deployment files exist"
	@echo "make clean              - Clean localhost deployment files"
	@echo "make clean-all          - Clean ALL deployment files (DANGER)"
	@echo "make test               - Run tests"
	@echo "make build              - Build contracts"
	@echo "make compile            - Compile contracts with checks"

# Network-specific deployments
deploy-mainnet:
	@echo "Deploying to MAINNET..."
	forge script script/DeploykPaymaster.s.sol --sig "run()" --rpc-url ${RPC_MAINNET} --broadcast --account keyDeployer --sender ${DEPLOYER_ADDRESS} --verify --etherscan-api-key ${ETHERSCAN_MAINNET_KEY} --slow
	@$(MAKE) format-output

deploy-mainnet-dry-run:
	@echo "[DRY-RUN] Simulating deployment to MAINNET..."
	forge script script/DeploykPaymaster.s.sol --sig "run()" --rpc-url ${RPC_MAINNET} --account keyDeployer --sender ${DEPLOYER_ADDRESS} --slow

deploy-sepolia:
	@echo "Deploying to SEPOLIA..."
	forge script script/DeploykPaymaster.s.sol --sig "run()" --rpc-url ${RPC_SEPOLIA} --broadcast --account keyDeployer --sender ${DEPLOYER_ADDRESS} --verify --etherscan-api-key ${ETHERSCAN_SEPOLIA_KEY} --slow
	@$(MAKE) format-output

deploy-sepolia-dry-run:
	@echo "[DRY-RUN] Simulating deployment to SEPOLIA..."
	forge script script/DeploykPaymaster.s.sol --sig "run()" --rpc-url ${RPC_SEPOLIA} --account keyDeployer --sender ${DEPLOYER_ADDRESS} --slow

deploy-localhost:
	@echo "Deploying to LOCALHOST..."
	forge script script/DeploykPaymaster.s.sol --sig "run()" --rpc-url http://localhost:8545 --broadcast --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --sender 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --slow
	@$(MAKE) format-output

deploy-localhost-dry-run:
	@echo "[DRY-RUN] Simulating deployment to LOCALHOST..."
	forge script script/DeploykPaymaster.s.sol --sig "run()" --rpc-url http://localhost:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --sender 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --slow

# Etherscan verification (mainnet)
verify-mainnet:
	@echo "Verifying contracts on MAINNET Etherscan..."
	@if [ ! -f "deployments/output/mainnet/addresses.json" ]; then \
		echo "No mainnet deployment found"; \
		exit 1; \
	fi
	@if [ ! -f "deployments/config/mainnet.json" ]; then \
		echo "No mainnet config found"; \
		exit 1; \
	fi
	@echo "Verifying kPaymaster..."
	@forge verify-contract $$(jq -r '.contracts.kPaymaster' deployments/output/mainnet/addresses.json) src/kPaymaster.sol:kPaymaster \
		--chain-id 1 \
		--etherscan-api-key ${ETHERSCAN_MAINNET_KEY} \
		--constructor-args $$(cast abi-encode "constructor(address,address,address)" \
			$$(jq -r '.roles.owner' deployments/config/mainnet.json) \
			$$(jq -r '.roles.treasury' deployments/config/mainnet.json) \
			$$(jq -r '.contracts.registry' deployments/config/mainnet.json)) \
		--watch || true
	@echo "Mainnet verification complete!"

# Etherscan verification (sepolia)
verify-sepolia:
	@echo "Verifying contracts on SEPOLIA Etherscan..."
	@if [ ! -f "deployments/output/sepolia/addresses.json" ]; then \
		echo "No sepolia deployment found"; \
		exit 1; \
	fi
	@if [ ! -f "deployments/config/sepolia.json" ]; then \
		echo "No sepolia config found"; \
		exit 1; \
	fi
	@echo "Verifying kPaymaster..."
	@forge verify-contract $$(jq -r '.contracts.kPaymaster' deployments/output/sepolia/addresses.json) src/kPaymaster.sol:kPaymaster \
		--chain-id 11155111 \
		--etherscan-api-key ${ETHERSCAN_SEPOLIA_KEY} \
		--constructor-args $$(cast abi-encode "constructor(address,address,address)" \
			$$(jq -r '.roles.owner' deployments/config/sepolia.json) \
			$$(jq -r '.roles.treasury' deployments/config/sepolia.json) \
			$$(jq -r '.contracts.registry' deployments/config/sepolia.json)) \
		--watch || true
	@echo "Sepolia verification complete!"

# Format JSON output files
format-output:
	@echo "Formatting JSON output files..."
	@for file in deployments/output/*/*.json; do \
		if [ -f "$$file" ]; then \
			echo "Formatting $$file"; \
			jq . "$$file" > "$$file.tmp" && mv "$$file.tmp" "$$file"; \
		fi; \
	done
	@echo "JSON files formatted!"

# Verification
verify:
	@echo "Verifying deployment..."
	@if [ ! -f "deployments/output/localhost/addresses.json" ] && [ ! -f "deployments/output/mainnet/addresses.json" ] && [ ! -f "deployments/output/sepolia/addresses.json" ]; then \
		echo "No deployment files found"; \
		exit 1; \
	fi
	@echo "Deployment files exist"
	@echo "Check deployments/output/ for contract addresses"

# Development helpers
test:
	@echo "Running tests..."
	forge test

build:
	forge fmt
	forge build --use $$(which solx)

compile:
	forge fmt --check
	forge build --sizes --skip test

clean:
	forge clean
	rm -rf deployments/output/localhost/addresses.json

clean-all:
	forge clean
	rm -rf deployments/output/*/addresses.json

# Documentation
docs:
	forge doc --serve --port 4000
