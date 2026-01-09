// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Script } from "forge-std/Script.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { console2 as console } from "forge-std/console2.sol";

/// @title DeploymentManager
/// @notice Manages deployment configuration and output for KamPaymaster
abstract contract DeploymentManager is Script {
    using stdJson for string;

    /// @notice Controls whether deployment logs are printed. Set to false in tests.
    bool public verbose = true;

    /// @notice Set verbose mode for logging
    function setVerbose(bool _verbose) public {
        verbose = _verbose;
    }

    struct NetworkConfig {
        string network;
        uint256 chainId;
        RoleAddresses roles;
    }

    struct RoleAddresses {
        address owner;
        address treasury;
        address executor;
    }

    struct DeploymentOutput {
        uint256 chainId;
        string network;
        uint256 timestamp;
        ContractAddresses contracts;
    }

    struct ContractAddresses {
        address kamPaymaster;
    }

    function getCurrentNetwork() internal view returns (string memory) {
        uint256 chainId = block.chainid;
        if (chainId == 1) return "mainnet";
        if (chainId == 11_155_111) return "sepolia";
        if (chainId == 31_337) return "localhost";
        return "localhost";
    }

    function isProduction() internal view returns (bool) {
        return vm.envOr("PRODUCTION", false);
    }

    function getDeploymentsPath() internal view returns (string memory) {
        string memory customPath = vm.envOr("PAYMASTER_DEPLOYMENT_BASE_PATH", string(""));
        if (bytes(customPath).length > 0) {
            return customPath;
        }
        return "deployments";
    }

    function readNetworkConfig() internal view returns (NetworkConfig memory config) {
        string memory network = getCurrentNetwork();
        string memory deploymentsPath = getDeploymentsPath();
        string memory configPath = string.concat(deploymentsPath, "/config/", network, ".json");
        require(vm.exists(configPath), string.concat("Config file not found: ", configPath));

        string memory json = vm.readFile(configPath);

        config.network = json.readString(".network");
        config.chainId = json.readUint(".chainId");

        // Parse role addresses
        config.roles.owner = json.readAddress(".roles.owner");
        config.roles.treasury = json.readAddress(".roles.treasury");
        config.roles.executor = json.readAddress(".roles.executor");

        return config;
    }

    function readDeploymentOutput() internal view returns (DeploymentOutput memory output) {
        string memory network = getCurrentNetwork();
        string memory deploymentsPath = getDeploymentsPath();
        string memory outputPath = string.concat(deploymentsPath, "/output/", network, "/addresses.json");

        if (!vm.exists(outputPath)) {
            output.network = network;
            output.chainId = block.chainid;
            return output;
        }

        string memory json = vm.readFile(outputPath);
        output.chainId = json.readUint(".chainId");
        output.network = json.readString(".network");
        output.timestamp = json.readUint(".timestamp");

        // Parse contract addresses
        if (json.keyExists(".contracts.kamPaymaster")) {
            output.contracts.kamPaymaster = json.readAddress(".contracts.kamPaymaster");
        }

        return output;
    }

    function writeContractAddress(string memory contractName, address contractAddress) internal {
        string memory network = getCurrentNetwork();
        string memory deploymentsPath = getDeploymentsPath();
        string memory outputPath = string.concat(deploymentsPath, "/output/", network, "/addresses.json");

        DeploymentOutput memory output = readDeploymentOutput();
        output.chainId = block.chainid;
        output.network = network;
        output.timestamp = block.timestamp;

        // Update the specific contract address
        if (keccak256(bytes(contractName)) == keccak256(bytes("kamPaymaster"))) {
            output.contracts.kamPaymaster = contractAddress;
        }

        string memory json = _serializeDeploymentOutput(output);
        vm.writeFile(outputPath, json);

        console.log(string.concat(contractName, " address written to: "), outputPath);
    }

    function _serializeDeploymentOutput(DeploymentOutput memory output) private pure returns (string memory) {
        string memory json = "{";
        json = string.concat(json, '"chainId":', vm.toString(output.chainId), ",");
        json = string.concat(json, '"network":"', output.network, '",');
        json = string.concat(json, '"timestamp":', vm.toString(output.timestamp), ",");
        json = string.concat(json, '"contracts":{');
        json = string.concat(json, '"kamPaymaster":"', vm.toString(output.contracts.kamPaymaster), '"');
        json = string.concat(json, "}}");

        return json;
    }

    function validateConfig(NetworkConfig memory config) internal pure {
        require(config.roles.owner != address(0), "Missing owner address");
        require(config.roles.treasury != address(0), "Missing treasury address");
        require(config.roles.executor != address(0), "Missing executor address");
    }

    function logConfig(NetworkConfig memory config) internal view {
        if (!verbose) return;
        console.log("=== DEPLOYMENT CONFIGURATION ===");
        console.log("Network:", config.network);
        console.log("Chain ID:", config.chainId);
        console.log("Owner:", config.roles.owner);
        console.log("Treasury:", config.roles.treasury);
        console.log("Executor:", config.roles.executor);
        console.log("===============================");
    }

    /*//////////////////////////////////////////////////////////////
                            LOGGING HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Log the script header with network info and config file paths
    function logScriptHeader(string memory scriptName) internal view {
        if (!verbose) return;

        string memory network = getCurrentNetwork();
        string memory deploymentsPath = getDeploymentsPath();
        string memory configPath = string.concat(deploymentsPath, "/config/", network, ".json");
        string memory outputPath = string.concat(deploymentsPath, "/output/", network, "/addresses.json");

        console.log("");
        console.log("================================================================================");
        console.log("  SCRIPT:", scriptName);
        console.log("================================================================================");
        console.log("");
        console.log("--- ENVIRONMENT ---");
        console.log("Network:          ", network);
        console.log("Chain ID:         ", block.chainid);
        console.log("Production mode:  ", isProduction() ? "YES" : "NO");
        console.log("Config file:      ", configPath);
        console.log("Output file:      ", outputPath);
        console.log("");
    }

    /// @notice Log all role addresses from config
    function logRoles(NetworkConfig memory config) internal view {
        if (!verbose) return;

        console.log("--- ROLE ADDRESSES ---");
        console.log("Owner:            ", config.roles.owner);
        console.log("Treasury:         ", config.roles.treasury);
        console.log("Executor:         ", config.roles.executor);
        console.log("");
    }

    /// @notice Log the broadcaster address that will execute transactions
    function logBroadcaster(address broadcaster) internal view {
        if (!verbose) return;

        console.log("--- BROADCASTER ---");
        console.log("Transactions will be sent from:", broadcaster);
        console.log("");
    }

    /// @notice Log a separator before execution begins
    function logExecutionStart() internal view {
        if (!verbose) return;

        console.log("================================================================================");
        console.log("  EXECUTING TRANSACTIONS");
        console.log("================================================================================");
        console.log("");
    }

    /// @dev Log a string message (only if verbose)
    function _log(string memory message) internal view {
        if (verbose) console.log(message);
    }

    /// @dev Log a string message with a string value (only if verbose)
    function _log(string memory message, string memory value) internal view {
        if (verbose) console.log(message, value);
    }

    /// @dev Log a string message with an address value (only if verbose)
    function _log(string memory message, address value) internal view {
        if (verbose) console.log(message, value);
    }

    /// @dev Log a string message with a uint256 value (only if verbose)
    function _log(string memory message, uint256 value) internal view {
        if (verbose) console.log(message, value);
    }
}
