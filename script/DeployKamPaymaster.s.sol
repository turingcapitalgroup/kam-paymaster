// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { KamPaymaster } from "../src/KamPaymaster.sol";
import { DeploymentManager } from "./utils/DeploymentManager.sol";
import { Script, console2 } from "forge-std/Script.sol";

/// @title DeployKamPaymasterScript
/// @notice Script to deploy the KamPaymaster contract using the deployment manager pattern
contract DeployKamPaymasterScript is Script, DeploymentManager {
    struct PaymasterDeployment {
        address kamPaymaster;
    }

    /// @notice Deploy KamPaymaster contract
    /// @param writeToJson If true, writes addresses to JSON (for real deployments). If false, only returns values (for
    /// tests)
    /// @return deployment Struct containing deployed address
    function run(bool writeToJson) public returns (PaymasterDeployment memory deployment) {
        // Read network configuration from JSON
        NetworkConfig memory config = readNetworkConfig();
        validateConfig(config);

        // Log script header and configuration
        logScriptHeader("DeployKamPaymaster");
        logRoles(config);
        logBroadcaster(config.roles.owner);
        logExecutionStart();

        vm.startBroadcast(config.roles.owner);

        // Deploy KamPaymaster with registry from config
        KamPaymaster paymaster = new KamPaymaster(config.roles.owner, config.roles.treasury, config.contracts.registry);

        // Set trusted executor
        paymaster.setTrustedExecutor(config.roles.executor, true);

        vm.stopBroadcast();

        _log("=== DEPLOYMENT COMPLETE ===");
        _log("KamPaymaster deployed at:", address(paymaster));
        _log("Network:", config.network);
        _log("Chain ID:", config.chainId);

        deployment = PaymasterDeployment({ kamPaymaster: address(paymaster) });

        // Write to JSON only if requested (for real deployments)
        if (writeToJson) {
            writeContractAddress("kamPaymaster", address(paymaster));
        }

        return deployment;
    }

    /// @notice Convenience wrapper for real deployments (writes to JSON)
    function run() public returns (PaymasterDeployment memory) {
        return run(true);
    }
}
