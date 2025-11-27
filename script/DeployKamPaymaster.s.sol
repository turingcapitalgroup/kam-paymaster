// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Script, console2 } from "forge-std/Script.sol";
import { KamPaymaster } from "../src/KamPaymaster.sol";

/// @title DeployKamPaymaster
/// @notice Script to deploy the KamPaymaster contract
contract DeployKamPaymaster is Script {
    /// @notice Configuration struct for deployment
    struct DeployConfig {
        address owner;
        address treasury;
        address registry;
        uint256 baseFee;
        uint256 gasMultiplier;
    }

    function run() external {
        // Load configuration from environment or use defaults
        DeployConfig memory config = _getConfig();

        console2.log("Deploying KamPaymaster...");
        console2.log("Owner:", config.owner);
        console2.log("Treasury:", config.treasury);
        console2.log("Registry:", config.registry);
        console2.log("Base Fee (bps):", config.baseFee);
        console2.log("Gas Multiplier:", config.gasMultiplier);

        vm.startBroadcast();

        KamPaymaster paymaster =
            new KamPaymaster(config.owner, config.treasury, config.registry, config.baseFee, config.gasMultiplier);

        console2.log("KamPaymaster deployed at:", address(paymaster));

        vm.stopBroadcast();
    }

    function _getConfig() internal view returns (DeployConfig memory) {
        // Try to load from environment variables
        address owner = vm.envOr("PAYMASTER_OWNER", msg.sender);
        address treasury = vm.envOr("PAYMASTER_TREASURY", msg.sender);
        address registry = vm.envOr("KAM_REGISTRY", address(0));
        uint256 baseFee = vm.envOr("PAYMASTER_BASE_FEE", uint256(100)); // 1% default
        uint256 gasMultiplier = vm.envOr("PAYMASTER_GAS_MULTIPLIER", uint256(1.2e18)); // 1.2x default

        require(registry != address(0), "KAM_REGISTRY environment variable not set");

        return DeployConfig({
            owner: owner,
            treasury: treasury,
            registry: registry,
            baseFee: baseFee,
            gasMultiplier: gasMultiplier
        });
    }
}

/// @title DeployKamPaymasterLocal
/// @notice Script to deploy the KamPaymaster for local testing
contract DeployKamPaymasterLocal is Script {
    function run() external {
        // Use anvil's default accounts for local testing
        address owner = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        address treasury = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

        // For local testing, we'll use a mock registry address
        // In reality, you'd deploy the registry first or use an existing one
        address registry = vm.envOr("KAM_REGISTRY", address(0x1234567890123456789012345678901234567890));

        uint256 baseFee = 100; // 1%
        uint256 gasMultiplier = 1.2e18; // 1.2x

        console2.log("Deploying KamPaymaster for local testing...");

        vm.startBroadcast();

        KamPaymaster paymaster = new KamPaymaster(owner, treasury, registry, baseFee, gasMultiplier);

        console2.log("KamPaymaster deployed at:", address(paymaster));

        // Set up additional executors for testing
        paymaster.setTrustedExecutor(0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC, true);

        console2.log("Setup complete!");

        vm.stopBroadcast();
    }
}

