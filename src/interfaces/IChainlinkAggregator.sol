// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title IChainlinkAggregator
/// @notice Minimal interface for Chainlink Price Feed aggregators
/// @dev Used to get asset/ETH prices for fee calculation
interface IChainlinkAggregator {
    /// @notice Get the latest round data from the price feed
    /// @return roundId The round ID
    /// @return answer The price (scaled by decimals())
    /// @return startedAt Timestamp when the round started
    /// @return updatedAt Timestamp when the round was updated
    /// @return answeredInRound The round ID in which the answer was computed
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);

    /// @notice Get the number of decimals for the price feed
    /// @return The number of decimals
    function decimals() external view returns (uint8);
}

