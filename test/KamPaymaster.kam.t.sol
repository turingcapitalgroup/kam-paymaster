// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { BaseVaultTest, DeploymentBaseTest } from "kam/test/utils/BaseVaultTest.sol";
import { _1_USDC } from "kam/test/utils/Constants.sol";

import { KamPaymaster } from "../src/KamPaymaster.sol";
import { IKamPaymaster } from "../src/interfaces/IKamPaymaster.sol";

import { IkStakingVault } from "kam/src/interfaces/IkStakingVault.sol";
import { kStakingVault } from "kam/src/kStakingVault/kStakingVault.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

/// @title KamPaymasterKAMTest
/// @notice Integration tests for KamPaymaster with actual KAM protocol infrastructure
/// @dev Extends BaseVaultTest to get full KAM protocol deployment and helpers
contract KamPaymasterKAMTest is BaseVaultTest {
    using SafeTransferLib for address;

    KamPaymaster public paymaster;
    address public executor;

    uint256 public constant USER_PRIVATE_KEY = 0xA11CE;
    address public testUser;

    uint48 constant DEFAULT_FEE = 100 * 1e6; // 100 USDC fee
    uint48 constant DEFAULT_MAX_FEE = 1000 * 1e6; // 1000 USDC max fee

    function setUp() public override {
        // Run full KAM deployment
        DeploymentBaseTest.setUp();

        // Set the vault to alphaVault for testing
        vault = IkStakingVault(address(alphaVault));

        // Mint kTokens to test users
        BaseVaultTest.setUp();

        // Setup paymaster
        executor = makeAddr("executor");
        testUser = vm.addr(USER_PRIVATE_KEY);

        // Deploy paymaster with treasury from KAM config
        paymaster = new KamPaymaster(users.owner, users.treasury);

        // Set executor as trusted
        vm.prank(users.owner);
        paymaster.setTrustedExecutor(executor, true);

        // Set paymaster as trusted forwarder on the vault
        vm.prank(users.admin);
        kStakingVault(payable(address(vault))).setTrustedForwarder(address(paymaster));

        // Mint kTokens to testUser
        _mintKTokenToUser(testUser, INITIAL_DEPOSIT, true);

        vm.label(address(paymaster), "KamPaymaster");
        vm.label(testUser, "TestUser");
        vm.label(executor, "Executor");
    }

    /*//////////////////////////////////////////////////////////////
                            SETUP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setUp() public view {
        assertEq(paymaster.owner(), users.owner);
        assertEq(paymaster.treasury(), users.treasury);
        assertTrue(paymaster.isTrustedExecutor(executor));
        assertTrue(paymaster.isTrustedExecutor(users.owner));
        assertGt(kUSD.balanceOf(testUser), 0);
    }

    /*//////////////////////////////////////////////////////////////
                        GASLESS STAKE FLOW TESTS
    //////////////////////////////////////////////////////////////*/

    function test_fullGaslessStakeFlow() public {
        uint48 stakeAmount = uint48(10_000 * _1_USDC);
        uint48 fee = uint48(100 * _1_USDC);

        // Execute gasless stake
        bytes32 requestId = _executeGaslessStake(testUser, stakeAmount, fee);

        // Close and settle batch
        bytes32 batchId = vault.getBatchId();
        vm.prank(users.relayer);
        vault.closeBatch(batchId, true);

        uint256 lastTotalAssets = vault.totalAssets();
        _executeBatchSettlement(address(vault), batchId, lastTotalAssets);

        // Execute gasless claim
        _executeGaslessClaimStakedShares(testUser, requestId, uint48(10 * _1_USDC));

        // Verify user received stkTokens
        assertGt(vault.balanceOf(testUser), 0);
    }

    function test_fullGaslessUnstakeFlow() public {
        // First stake to get stkTokens
        _setupUserWithStkTokens(testUser, 10_000 * _1_USDC);

        uint256 stkBalance = vault.balanceOf(testUser);
        require(stkBalance > 0, "No stkTokens to unstake");

        uint48 unstakeAmount = uint48(stkBalance / 2);
        uint48 fee = uint48(100 * _1_USDC);

        // Execute gasless unstake
        bytes32 requestId = _executeGaslessUnstake(testUser, unstakeAmount, fee);

        // Close and settle batch
        bytes32 batchId = vault.getBatchId();
        vm.prank(users.relayer);
        vault.closeBatch(batchId, true);

        uint256 lastTotalAssets = vault.totalAssets();
        _executeBatchSettlement(address(vault), batchId, lastTotalAssets);

        // Execute gasless claim
        uint256 kTokenBalanceBefore = kUSD.balanceOf(testUser);
        _executeGaslessClaimUnstakedAssets(testUser, requestId, uint48(10 * _1_USDC));

        // Verify user received kTokens back
        assertGt(kUSD.balanceOf(testUser), kTokenBalanceBefore);
    }

    function test_zeroFeeStake() public {
        uint48 stakeAmount = uint48(1000 * _1_USDC);
        uint48 fee = 0;

        uint256 treasuryBefore = kUSD.balanceOf(users.treasury);

        _executeGaslessStake(testUser, stakeAmount, fee);

        // No fee collected
        assertEq(kUSD.balanceOf(users.treasury), treasuryBefore);
    }

    function test_nonceIncrementsAfterEachOperation() public {
        assertEq(paymaster.nonces(testUser), 0);

        _executeGaslessStake(testUser, uint48(1000 * _1_USDC), uint48(10 * _1_USDC));
        assertEq(paymaster.nonces(testUser), 1);

        _executeGaslessStake(testUser, uint48(1000 * _1_USDC), uint48(10 * _1_USDC));
        assertEq(paymaster.nonces(testUser), 2);
    }

    /*//////////////////////////////////////////////////////////////
                        REVERT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_revert_notTrustedExecutor() public {
        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: testUser,
            nonce: 0,
            deadline: uint48(block.timestamp + 1 hours),
            vault: address(vault),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: 1000 * 1e6,
            recipient: testUser
        });

        IKamPaymaster.PermitSignature memory permitForForwarder = IKamPaymaster.PermitSignature({
            value: DEFAULT_FEE, deadline: uint48(block.timestamp + 1 hours), v: 27, r: bytes32(0), s: bytes32(0)
        });

        IKamPaymaster.PermitSignature memory permitForVault = IKamPaymaster.PermitSignature({
            value: 900 * 1e6, deadline: uint48(block.timestamp + 1 hours), v: 27, r: bytes32(0), s: bytes32(0)
        });

        address randomUser = makeAddr("random");
        vm.prank(randomUser);
        vm.expectRevert(IKamPaymaster.NotTrustedExecutor.selector);
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, "", DEFAULT_FEE);
    }

    function test_revert_expiredDeadline() public {
        uint48 stakeAmount = uint48(1000 * _1_USDC);
        uint48 fee = uint48(100 * _1_USDC);
        uint48 netAmount = stakeAmount - fee;
        uint48 permitDeadline = uint48(block.timestamp + 1 hours);

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: testUser,
            nonce: 0,
            deadline: uint48(block.timestamp - 1), // Expired
            vault: address(vault),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kUSD), testUser, address(paymaster), fee, permitDeadline, kUSD.nonces(testUser), USER_PRIVATE_KEY
        );

        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kUSD),
            testUser,
            address(vault),
            netAmount,
            permitDeadline,
            kUSD.nonces(testUser) + 1,
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.RequestExpired.selector);
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, requestSig, fee);
    }

    function test_revert_invalidNonce() public {
        uint48 stakeAmount = uint48(1000 * _1_USDC);
        uint48 fee = uint48(100 * _1_USDC);
        uint48 netAmount = stakeAmount - fee;
        uint48 deadline = uint48(block.timestamp + 1 hours);

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: testUser,
            nonce: 999, // Wrong nonce
            deadline: deadline,
            vault: address(vault),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kUSD), testUser, address(paymaster), fee, deadline, kUSD.nonces(testUser), USER_PRIVATE_KEY
        );

        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kUSD), testUser, address(vault), netAmount, deadline, kUSD.nonces(testUser) + 1, USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.InvalidNonce.selector);
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, requestSig, fee);
    }

    function test_revert_insufficientAmountForFee() public {
        uint48 tinyAmount = 1;
        uint48 deadline = uint48(block.timestamp + 1 hours);

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: testUser,
            nonce: 0,
            deadline: deadline,
            vault: address(vault),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: tinyAmount,
            recipient: testUser
        });

        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kUSD), testUser, address(paymaster), DEFAULT_FEE, deadline, kUSD.nonces(testUser), USER_PRIVATE_KEY
        );

        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kUSD), testUser, address(vault), tinyAmount, deadline, kUSD.nonces(testUser) + 1, USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.InsufficientAmountForFee.selector);
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, requestSig, DEFAULT_FEE);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _executeGaslessStake(address user, uint48 stakeAmount, uint48 fee) internal returns (bytes32 requestId) {
        uint48 deadline = uint48(block.timestamp + 1 hours);
        uint48 netAmount = stakeAmount - fee;

        IKamPaymaster.StakeRequest memory stakeRequest = IKamPaymaster.StakeRequest({
            user: user,
            nonce: uint48(paymaster.nonces(user)),
            deadline: deadline,
            vault: address(vault),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: user
        });

        IKamPaymaster.PermitSignature memory permitForForwarder;
        if (fee > 0) {
            permitForForwarder = _createPermitSignature(
                address(kUSD), user, address(paymaster), fee, deadline, kUSD.nonces(user), USER_PRIVATE_KEY
            );
        } else {
            permitForForwarder =
                IKamPaymaster.PermitSignature({ value: 0, deadline: deadline, v: 27, r: bytes32(0), s: bytes32(0) });
        }

        uint256 vaultPermitNonce = fee > 0 ? kUSD.nonces(user) + 1 : kUSD.nonces(user);
        uint48 vaultPermitAmount = fee > 0 ? netAmount : stakeAmount;

        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kUSD), user, address(vault), vaultPermitAmount, deadline, vaultPermitNonce, USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(stakeRequest, USER_PRIVATE_KEY);

        uint256 userKTokenBefore = kUSD.balanceOf(user);
        uint256 treasuryBefore = kUSD.balanceOf(users.treasury);

        vm.prank(executor);
        requestId =
            paymaster.executeRequestStakeWithPermit(stakeRequest, permitForForwarder, permitForVault, requestSig, fee);

        uint256 feeCollected = kUSD.balanceOf(users.treasury) - treasuryBefore;

        assertEq(kUSD.balanceOf(user), userKTokenBefore - stakeAmount);
        assertEq(feeCollected, fee);
    }

    function _executeGaslessUnstake(
        address user,
        uint48 unstakeAmount,
        uint48 fee
    )
        internal
        returns (bytes32 requestId)
    {
        uint48 deadline = uint48(block.timestamp + 1 hours);

        IKamPaymaster.UnstakeRequest memory unstakeRequest = IKamPaymaster.UnstakeRequest({
            user: user,
            nonce: uint48(paymaster.nonces(user)),
            deadline: deadline,
            vault: address(vault),
            maxFee: DEFAULT_MAX_FEE,
            stkTokenAmount: unstakeAmount,
            recipient: user
        });

        IKamPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(vault), user, address(paymaster), fee, deadline, _getVaultNonces(user), USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createUnstakeRequestSignature(unstakeRequest, USER_PRIVATE_KEY);

        uint256 userStkBefore = vault.balanceOf(user);
        uint256 treasuryBefore = vault.balanceOf(users.treasury);

        vm.prank(executor);
        requestId = paymaster.executeRequestUnstakeWithPermit(unstakeRequest, permitSig, requestSig, fee);

        uint256 feeCollected = vault.balanceOf(users.treasury) - treasuryBefore;

        assertEq(vault.balanceOf(user), userStkBefore - unstakeAmount);
        assertEq(feeCollected, fee);
    }

    function _executeGaslessClaimStakedShares(address user, bytes32 requestId, uint48 fee) internal {
        uint48 deadline = uint48(block.timestamp + 1 hours);

        IKamPaymaster.ClaimRequest memory claimRequest = IKamPaymaster.ClaimRequest({
            user: user,
            nonce: uint48(paymaster.nonces(user)),
            deadline: deadline,
            vault: address(vault),
            maxFee: DEFAULT_MAX_FEE,
            requestId: requestId
        });

        // User approves paymaster for fee (in stkTokens, which will be claimed)
        // For claims, the user needs to approve after they receive tokens
        // Since we're claiming stkTokens, user will receive them and can then pay fee
        bytes memory claimSig = _createClaimRequestSignature(claimRequest, USER_PRIVATE_KEY);

        // For claim, user needs pre-approval since they don't have tokens yet
        // Skip fee for claim in this flow or use permit
        IKamPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(vault), user, address(paymaster), fee, deadline, _getVaultNonces(user), USER_PRIVATE_KEY
        );

        uint256 userStkBefore = vault.balanceOf(user);

        vm.prank(executor);
        paymaster.executeClaimStakedSharesWithPermit(claimRequest, permitSig, claimSig, fee);

        assertGt(vault.balanceOf(user), userStkBefore);
    }

    function _executeGaslessClaimUnstakedAssets(address user, bytes32 requestId, uint48 fee) internal {
        uint48 deadline = uint48(block.timestamp + 1 hours);

        IKamPaymaster.ClaimRequest memory claimRequest = IKamPaymaster.ClaimRequest({
            user: user,
            nonce: uint48(paymaster.nonces(user)),
            deadline: deadline,
            vault: address(vault),
            maxFee: DEFAULT_MAX_FEE,
            requestId: requestId
        });

        IKamPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(kUSD), user, address(paymaster), fee, deadline, kUSD.nonces(user), USER_PRIVATE_KEY
        );

        bytes memory claimSig = _createClaimRequestSignature(claimRequest, USER_PRIVATE_KEY);

        uint256 userKTokenBefore = kUSD.balanceOf(user);

        vm.prank(executor);
        paymaster.executeClaimUnstakedAssetsWithPermit(claimRequest, permitSig, claimSig, fee);

        assertGt(kUSD.balanceOf(user), userKTokenBefore);
    }

    function _setupUserWithStkTokens(address user, uint256 amount) internal {
        // Mint kTokens
        _mintKTokenToUser(user, amount, true);

        // Request staking
        vm.prank(user);
        kUSD.approve(address(vault), amount);

        bytes32 batchId = vault.getBatchId();

        vm.prank(user);
        bytes32 requestId = vault.requestStake(user, amount);

        // Close and settle batch
        vm.prank(users.relayer);
        vault.closeBatch(batchId, true);

        uint256 lastTotalAssets = vault.totalAssets();
        _executeBatchSettlement(address(vault), batchId, lastTotalAssets);

        // Claim staked shares to get stkTokens
        vm.prank(user);
        vault.claimStakedShares(requestId);
    }

    function _createPermitSignature(
        address token,
        address owner_,
        address spender,
        uint48 value,
        uint48 deadline,
        uint256 nonce,
        uint256 privateKey
    )
        internal
        view
        returns (IKamPaymaster.PermitSignature memory)
    {
        bytes32 PERMIT_TYPEHASH =
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

        bytes32 domainSeparator = _getTokenDomainSeparator(token);

        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, owner_, spender, uint256(value), nonce, uint256(deadline)));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return IKamPaymaster.PermitSignature({ value: value, deadline: deadline, v: v, r: r, s: s });
    }

    function _getTokenDomainSeparator(address token) internal view returns (bytes32) {
        // Call DOMAIN_SEPARATOR() on the token
        (bool success, bytes memory data) = token.staticcall(abi.encodeWithSignature("DOMAIN_SEPARATOR()"));
        require(success, "Failed to get DOMAIN_SEPARATOR");
        return abi.decode(data, (bytes32));
    }

    function _createStakeRequestSignature(
        IKamPaymaster.StakeRequest memory request,
        uint256 privateKey
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                paymaster.STAKE_REQUEST_TYPEHASH(),
                request.user,
                request.nonce,
                request.deadline,
                request.vault,
                request.maxFee,
                request.kTokenAmount,
                request.recipient
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", paymaster.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return abi.encodePacked(r, s, v);
    }

    function _createUnstakeRequestSignature(
        IKamPaymaster.UnstakeRequest memory request,
        uint256 privateKey
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                paymaster.UNSTAKE_REQUEST_TYPEHASH(),
                request.user,
                request.nonce,
                request.deadline,
                request.vault,
                request.maxFee,
                request.stkTokenAmount,
                request.recipient
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", paymaster.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return abi.encodePacked(r, s, v);
    }

    function _createClaimRequestSignature(
        IKamPaymaster.ClaimRequest memory request,
        uint256 privateKey
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                paymaster.CLAIM_REQUEST_TYPEHASH(),
                request.user,
                request.nonce,
                request.deadline,
                request.vault,
                request.maxFee,
                request.requestId
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", paymaster.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return abi.encodePacked(r, s, v);
    }

    function _getVaultNonces(address user) internal view returns (uint256) {
        return kStakingVault(payable(address(vault))).nonces(user);
    }
}
