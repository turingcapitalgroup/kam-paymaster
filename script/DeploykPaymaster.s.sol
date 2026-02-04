// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { kPaymaster } from "../src/kPaymaster.sol";
import { DeploymentManager } from "./utils/DeploymentManager.sol";
import { Script } from "forge-std/Script.sol";

/// @title DeploykPaymasterScript
/// @notice Script to deploy the kPaymaster contract using the deployment manager pattern
contract DeploykPaymasterScript is Script, DeploymentManager {
    struct PaymasterDeployment {
        address kPaymaster;
    }

    /// @notice Deploy kPaymaster contract
    /// @param writeToJson If true, writes addresses to JSON (for real deployments). If false, only returns values (for
    /// tests)
    /// @return deployment Struct containing deployed address
    function run(bool writeToJson) public returns (PaymasterDeployment memory deployment) {
        // Read network configuration from JSON
        NetworkConfig memory config = readNetworkConfig();
        validateConfig(config);

        // Log script header and configuration
        logScriptHeader("DeploykPaymaster");
        logRoles(config);
        logBroadcaster(config.roles.deployer);
        logExecutionStart();

        vm.startBroadcast(config.roles.deployer);

        // Deploy kPaymaster with registry from config
        kPaymaster paymaster = new kPaymaster(config.roles.owner, config.roles.treasury, config.contracts.registry);

        // Set trusted executor
        paymaster.setTrustedExecutor(config.roles.executor, true);

        vm.stopBroadcast();

        _log("=== DEPLOYMENT COMPLETE ===");
        _log("kPaymaster deployed at:", address(paymaster));
        _log("Network:", config.network);
        _log("Chain ID:", config.chainId);

        deployment = PaymasterDeployment({ kPaymaster: address(paymaster) });

        // Write to JSON only if requested (for real deployments)
        if (writeToJson) {
            writeContractAddress("kPaymaster", address(paymaster));
        }

        return deployment;
    }

    /// @notice Convenience wrapper for real deployments (writes to JSON)
    function run() public returns (PaymasterDeployment memory) {
        return run(true);
    }
}
