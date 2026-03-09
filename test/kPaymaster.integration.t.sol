// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { IkPaymaster } from "../src/interfaces/IkPaymaster.sol";
import { kPaymaster } from "../src/kPaymaster.sol";

import { _1_USDC } from "kam/test/utils/Constants.sol";
import { DeploymentBaseTest } from "kam/test/utils/DeploymentBaseTest.sol";

import { IVaultBatch } from "kam/src/interfaces/IVaultBatch.sol";
import { IkStakingVault } from "kam/src/interfaces/IkStakingVault.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

interface IERC20Permit {
    function nonces(address owner) external view returns (uint256);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

contract kPaymasterIntegrationTest is DeploymentBaseTest {
    using SafeTransferLib for address;

    kPaymaster public paymaster;
    address public executor;

    uint256 public constant USER_PRIVATE_KEY = 0xA11CE;
    address public testUser;

    uint96 constant DEFAULT_FEE = 100 * 1e6; // 100 USDC
    uint96 constant DEFAULT_MAX_FEE = 1000 * 1e6; // 1000 USDC

    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    function setUp() public override {
        DeploymentBaseTest.setUp();

        testUser = vm.addr(USER_PRIVATE_KEY);
        executor = makeAddr("executor");

        // Set settlement cooldown to 0 for instant test execution
        vm.prank(users.admin);
        assetRouter.setSettlementCooldown(0);

        // Mint kUSD to testUser via the full protocol minting flow
        _mintKTokensToTestUser(200_000 * _1_USDC);

        // Deploy paymaster with real registry
        paymaster = new kPaymaster(users.owner, users.treasury, address(registry));

        // Configure executor
        vm.prank(users.owner);
        paymaster.setTrustedExecutor(executor, true);

        // Set paymaster as trusted forwarder on dnVault
        vm.prank(users.owner);
        dnVault.setTrustedForwarder(address(paymaster));

        vm.label(address(paymaster), "kPaymaster");
        vm.label(testUser, "TestUser");
        vm.label(executor, "Executor");
    }

    /* //////////////////////////////////////////////////////////////
                          MINT HELPERS
    //////////////////////////////////////////////////////////////*/

    function _mintKTokensToTestUser(uint256 amount) internal {
        mockUSDC.mint(users.institution, amount);

        vm.startPrank(users.institution);
        address(tokens.usdc).safeApprove(address(minter), type(uint256).max);
        minter.mint(tokens.usdc, users.institution, amount);
        vm.stopPrank();

        // Close and settle minter batch
        bytes32 batchId = minter.getBatchId(tokens.usdc);
        vm.prank(users.relayer);
        IkStakingVault(address(minter)).closeBatch(batchId, true);

        uint256 totalAssets = assetRouter.virtualBalance(address(minter), tokens.usdc);
        _executeBatchSettlement(address(minter), batchId, totalAssets);

        // Transfer kUSD from institution to testUser
        vm.prank(users.institution);
        kUSD.transfer(testUser, amount);
    }

    /* //////////////////////////////////////////////////////////////
                      BATCH SETTLEMENT HELPERS
    //////////////////////////////////////////////////////////////*/

    function _executeBatchSettlement(address vaultAddress, bytes32 batchId, uint256 totalAssets) internal {
        vm.prank(users.relayer);
        bytes32 proposalId = assetRouter.proposeSettleBatch(tokens.usdc, vaultAddress, batchId, totalAssets, 0, 0);

        (bool canExecute,) = assetRouter.canExecuteProposal(proposalId);
        if (!canExecute) {
            vm.prank(users.guardian);
            assetRouter.acceptProposal(proposalId);
        }

        assetRouter.executeSettleBatch(proposalId);
    }

    function _closeBatchAndSettle(address vaultAddr, bytes32 batchId, uint256 totalAssets) internal {
        vm.prank(users.relayer);
        IVaultBatch(vaultAddr).closeBatch(batchId, true);

        _executeBatchSettlement(vaultAddr, batchId, totalAssets);
    }

    /* //////////////////////////////////////////////////////////////
                          SIGNATURE HELPERS
    //////////////////////////////////////////////////////////////*/

    function _createPermitSignature(
        address token,
        address owner_,
        address spender,
        uint256 value,
        uint256 deadline,
        uint256 nonce,
        uint256 privateKey
    )
        internal
        view
        returns (IkPaymaster.PermitSignature memory)
    {
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner_, spender, value, nonce, deadline));

        bytes32 domainSeparator = IERC20Permit(token).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return IkPaymaster.PermitSignature({ value: value, deadline: deadline, v: v, r: r, s: s });
    }

    function _createStakeWithAutoclaimRequestSignature(
        IkPaymaster.StakeWithAutoclaimRequest memory request,
        uint256 privateKey
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                paymaster.STAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH(),
                request.user,
                request.nonce,
                request.vault,
                request.deadline,
                request.recipient,
                request.maxFee,
                request.kTokenAmount
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", paymaster.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return abi.encodePacked(r, s, v);
    }

    function _createUnstakeWithAutoclaimRequestSignature(
        IkPaymaster.UnstakeWithAutoclaimRequest memory request,
        uint256 privateKey
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                paymaster.UNSTAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH(),
                request.user,
                request.nonce,
                request.vault,
                request.deadline,
                request.recipient,
                request.maxFee,
                request.stkTokenAmount
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", paymaster.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return abi.encodePacked(r, s, v);
    }

    /* //////////////////////////////////////////////////////////////
                          STAKE HELPERS
    //////////////////////////////////////////////////////////////*/

    function _executeGaslessStakeWithAutoclaim(uint96 stakeAmount, uint96 fee) internal returns (bytes32 requestId) {
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.StakeWithAutoclaimRequest memory stakeRequest = IkPaymaster.StakeWithAutoclaimRequest({
            user: testUser,
            nonce: uint96(paymaster.nonces(testUser)),
            vault: address(dnVault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kUSD), testUser, address(paymaster), stakeAmount, deadline, kUSD.nonces(testUser), USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(stakeRequest, USER_PRIVATE_KEY);

        uint256 userKTokenBefore = kUSD.balanceOf(testUser);
        uint256 treasuryBefore = kUSD.balanceOf(users.treasury);

        vm.prank(executor);
        requestId = paymaster.executeRequestStakeWithAutoclaimWithPermit(stakeRequest, permit, requestSig, fee);

        uint256 feeCollected = kUSD.balanceOf(users.treasury) - treasuryBefore;

        assertEq(kUSD.balanceOf(testUser), userKTokenBefore - stakeAmount);
        assertEq(feeCollected, fee);
    }

    function _executeGaslessStakeWithAutoclaimSimple(
        address userAddr,
        uint96 amount,
        uint96 fee
    )
        internal
        returns (bytes32)
    {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 tokenNonce = kUSD.nonces(userAddr);

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: userAddr,
            nonce: uint96(paymaster.nonces(userAddr)),
            vault: address(dnVault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: amount,
            recipient: userAddr
        });

        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kUSD), userAddr, address(paymaster), amount, deadline, tokenNonce, USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        return paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permit, requestSig, fee);
    }

    /// @dev Performs a direct stake + settle + claim to give the user stkTokens
    function _performDirectStake(address userAddr, uint256 amount) internal {
        vm.startPrank(userAddr);
        kUSD.approve(address(dnVault), amount);

        bytes32 batchId = dnVault.getBatchId();
        uint256 totalAssetsBefore = dnVault.totalAssets();

        bytes32 requestId = dnVault.requestStake(userAddr, userAddr, amount);
        vm.stopPrank();

        _closeBatchAndSettle(address(dnVault), batchId, totalAssetsBefore);

        vm.prank(userAddr);
        dnVault.claimStakedShares(requestId);
    }

    /* //////////////////////////////////////////////////////////////
                              TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setUp() public view {
        assertEq(paymaster.owner(), users.owner);
        assertEq(paymaster.treasury(), users.treasury);
        assertTrue(paymaster.isTrustedExecutor(executor));
        assertGt(kUSD.balanceOf(testUser), 0);
    }

    function test_fullGaslessStakeWithAutoclaimFlow() public {
        uint96 stakeAmount = uint96(10_000 * _1_USDC);

        // Capture vault batch before stake
        bytes32 batchId = dnVault.getBatchId();
        uint256 totalAssetsBefore = dnVault.totalAssets();

        // Execute stake with autoclaim via paymaster
        bytes32 requestId = _executeGaslessStakeWithAutoclaim(stakeAmount, DEFAULT_FEE);

        // Verify autoclaim is registered
        assertTrue(paymaster.canAutoclaim(requestId));

        // Close and settle vault batch
        _closeBatchAndSettle(address(dnVault), batchId, totalAssetsBefore);

        // Execute autoclaim
        uint256 userStkBefore = dnVault.balanceOf(testUser);

        vm.prank(executor);
        paymaster.executeAutoclaimStakedShares(requestId);

        // Verify user received shares and autoclaim is consumed
        assertGt(dnVault.balanceOf(testUser), userStkBefore);
        assertFalse(paymaster.canAutoclaim(requestId));
    }

    function test_fullGaslessUnstakeWithAutoclaimFlow() public {
        // First do a direct stake to give testUser stkTokens
        _performDirectStake(testUser, 20_000 * _1_USDC);

        uint256 userStkBalance = dnVault.balanceOf(testUser);
        require(userStkBalance > 0, "No stkTokens to unstake");

        uint96 unstakeAmount = uint96(userStkBalance / 2);
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.UnstakeWithAutoclaimRequest memory unstakeRequest = IkPaymaster.UnstakeWithAutoclaimRequest({
            user: testUser,
            nonce: uint96(paymaster.nonces(testUser)),
            vault: address(dnVault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            stkTokenAmount: unstakeAmount,
            recipient: testUser
        });

        IkPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(dnVault),
            testUser,
            address(paymaster),
            unstakeAmount,
            deadline,
            IERC20Permit(address(dnVault)).nonces(testUser),
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createUnstakeWithAutoclaimRequestSignature(unstakeRequest, USER_PRIVATE_KEY);

        // Capture vault batch before unstake
        bytes32 batchId = dnVault.getBatchId();
        uint256 totalAssetsBefore = dnVault.totalAssets();

        uint256 userStkBefore = dnVault.balanceOf(testUser);
        uint256 treasuryStkBefore = dnVault.balanceOf(users.treasury);

        vm.prank(executor);
        bytes32 requestId =
            paymaster.executeRequestUnstakeWithAutoclaimWithPermit(unstakeRequest, permitSig, requestSig, DEFAULT_FEE);

        // Verify fee collected and stkTokens pulled
        assertEq(dnVault.balanceOf(testUser), userStkBefore - unstakeAmount);
        assertEq(dnVault.balanceOf(users.treasury) - treasuryStkBefore, DEFAULT_FEE);

        // Verify autoclaim is registered
        assertTrue(paymaster.canAutoclaim(requestId));

        // Close and settle vault batch
        _closeBatchAndSettle(address(dnVault), batchId, totalAssetsBefore);

        // Execute autoclaim
        uint256 userKTokenBefore = kUSD.balanceOf(testUser);

        vm.prank(executor);
        paymaster.executeAutoclaimUnstakedAssets(requestId);

        // Verify user received kTokens and autoclaim is consumed
        assertGt(kUSD.balanceOf(testUser), userKTokenBefore);
        assertFalse(paymaster.canAutoclaim(requestId));
    }

    function test_revert_expiredDeadline() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint256 permitDeadline = block.timestamp + 1 hours;

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: testUser,
            nonce: 0,
            vault: address(dnVault),
            deadline: uint96(block.timestamp - 1),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kUSD),
            testUser,
            address(paymaster),
            stakeAmount,
            permitDeadline,
            kUSD.nonces(testUser),
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_RequestExpired.selector);
        paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permit, requestSig, DEFAULT_FEE);
    }

    function test_revert_invalidNonce() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: testUser,
            nonce: 999,
            vault: address(dnVault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kUSD), testUser, address(paymaster), stakeAmount, deadline, kUSD.nonces(testUser), USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_InvalidNonce.selector);
        paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permit, requestSig, DEFAULT_FEE);
    }

    function test_revert_notTrustedExecutor() public {
        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: testUser,
            nonce: 0,
            vault: address(dnVault),
            deadline: uint96(block.timestamp + 1 hours),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: 1000 * 1e6,
            recipient: testUser
        });

        IkPaymaster.PermitSignature memory permit = IkPaymaster.PermitSignature({
            value: 1000 * 1e6, deadline: block.timestamp + 1 hours, v: 27, r: bytes32(0), s: bytes32(0)
        });

        address randomUser = makeAddr("random");
        vm.prank(randomUser);
        vm.expectRevert(IkPaymaster.kPaymaster_NotTrustedExecutor.selector);
        paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permit, "", DEFAULT_FEE);
    }

    function test_revert_insufficientAmountForFee() public {
        uint96 tinyAmount = 1;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: testUser,
            nonce: 0,
            vault: address(dnVault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: tinyAmount,
            recipient: testUser
        });

        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kUSD), testUser, address(paymaster), tinyAmount, deadline, kUSD.nonces(testUser), USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_InsufficientAmountForFee.selector);
        paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permit, requestSig, DEFAULT_FEE);
    }

    function test_nonceIncrementsAfterEachOperation() public {
        assertEq(paymaster.nonces(testUser), 0);

        _executeGaslessStakeWithAutoclaimSimple(testUser, uint96(1000 * _1_USDC), uint96(10 * _1_USDC));
        assertEq(paymaster.nonces(testUser), 1);

        _executeGaslessStakeWithAutoclaimSimple(testUser, uint96(1000 * _1_USDC), uint96(10 * _1_USDC));
        assertEq(paymaster.nonces(testUser), 2);
    }

    function test_zeroFeeStakeWithAutoclaim() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 0;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.StakeWithAutoclaimRequest memory stakeRequest = IkPaymaster.StakeWithAutoclaimRequest({
            user: testUser,
            nonce: uint96(paymaster.nonces(testUser)),
            vault: address(dnVault),
            deadline: uint96(deadline),
            maxFee: 0,
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kUSD), testUser, address(paymaster), stakeAmount, deadline, kUSD.nonces(testUser), USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(stakeRequest, USER_PRIVATE_KEY);

        uint256 treasuryBefore = kUSD.balanceOf(users.treasury);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestStakeWithAutoclaimWithPermit(stakeRequest, permit, requestSig, fee);

        assertEq(kUSD.balanceOf(users.treasury), treasuryBefore); // No fee collected
        assertTrue(paymaster.canAutoclaim(requestId));
    }
}
