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

contract kPaymasterTest is DeploymentBaseTest {
    using SafeTransferLib for address;

    kPaymaster public paymaster;
    address public executor;

    uint256 public constant USER_PRIVATE_KEY = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    address public user;

    uint96 constant DEFAULT_MAX_FEE = 100 * 1e6;

    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    function setUp() public override {
        DeploymentBaseTest.setUp();

        user = vm.addr(USER_PRIVATE_KEY);
        executor = makeAddr("executor");

        // Set settlement cooldown to 0 for instant test execution
        vm.prank(users.admin);
        assetRouter.setSettlementCooldown(0);

        // Mint kUSD to user via the full protocol minting flow
        _mintKTokensToUser(1_000_000 * _1_USDC);

        // Deploy paymaster with real registry
        paymaster = new kPaymaster(users.owner, users.treasury, address(registry));

        // Configure executor
        vm.prank(users.owner);
        paymaster.setTrustedExecutor(executor, true);

        // Set paymaster as trusted forwarder on dnVault
        vm.prank(users.owner);
        dnVault.setTrustedForwarder(address(paymaster));

        // Give user stkTokens for unstake tests via direct stake
        _performDirectStake(user, 500_000 * _1_USDC);

        vm.label(address(paymaster), "kPaymaster");
        vm.label(user, "User");
        vm.label(executor, "Executor");
    }

    /* //////////////////////////////////////////////////////////////
                          MINT & STAKE HELPERS
    //////////////////////////////////////////////////////////////*/

    function _mintKTokensToUser(uint256 amount) internal {
        mockUSDC.mint(users.institution, amount);

        vm.startPrank(users.institution);
        address(tokens.usdc).safeApprove(address(minter), type(uint256).max);
        minter.mint(tokens.usdc, users.institution, amount);
        vm.stopPrank();

        bytes32 batchId = minter.getBatchId(tokens.usdc);
        vm.prank(users.relayer);
        IkStakingVault(address(minter)).closeBatch(batchId, true);

        uint256 totalAssets = assetRouter.virtualBalance(address(minter), tokens.usdc);
        _executeBatchSettlement(address(minter), batchId, totalAssets);

        vm.prank(users.institution);
        kUSD.transfer(user, amount);
    }

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

    function _stakeWithAutoclaimAndSettle(uint96 stakeAmount, uint96 fee) internal returns (bytes32 requestId) {
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: uint96(paymaster.nonces(user)),
            vault: address(dnVault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(user);
        kUSD.approve(address(paymaster), stakeAmount);

        bytes32 batchId = dnVault.getBatchId();
        uint256 totalAssetsBefore = dnVault.totalAssets();

        vm.prank(executor);
        requestId = paymaster.executeRequestStakeWithAutoclaim(request, requestSig, fee);

        _closeBatchAndSettle(address(dnVault), batchId, totalAssetsBefore);
    }

    function _unstakeWithAutoclaimAndSettle(uint96 unstakeAmount, uint96 fee) internal returns (bytes32 requestId) {
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.UnstakeWithAutoclaimRequest memory request = IkPaymaster.UnstakeWithAutoclaimRequest({
            user: user,
            nonce: uint96(paymaster.nonces(user)),
            vault: address(dnVault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            stkTokenAmount: unstakeAmount
        });

        bytes memory requestSig = _createUnstakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(user);
        dnVault.approve(address(paymaster), unstakeAmount);

        bytes32 batchId = dnVault.getBatchId();
        uint256 totalAssetsBefore = dnVault.totalAssets();

        vm.prank(executor);
        requestId = paymaster.executeRequestUnstakeWithAutoclaim(request, requestSig, fee);

        _closeBatchAndSettle(address(dnVault), batchId, totalAssetsBefore);
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
                      CONSTRUCTOR & ADMIN TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constructor() public view {
        assertEq(paymaster.owner(), users.owner);
        assertEq(paymaster.treasury(), users.treasury);
        assertTrue(paymaster.isTrustedExecutor(users.owner));
    }

    function test_setTrustedExecutor() public {
        address newExecutor = makeAddr("newExecutor");

        vm.prank(users.owner);
        paymaster.setTrustedExecutor(newExecutor, true);
        assertTrue(paymaster.isTrustedExecutor(newExecutor));

        vm.prank(users.owner);
        paymaster.setTrustedExecutor(newExecutor, false);
        assertFalse(paymaster.isTrustedExecutor(newExecutor));
    }

    function test_revert_notTrustedExecutor() public {
        address notExecutor = makeAddr("notExecutor");

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(dnVault),
            deadline: uint96(block.timestamp + 1 hours),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: 1000 * 1e6,
            recipient: user
        });

        IkPaymaster.PermitSignature memory permit = IkPaymaster.PermitSignature({
            value: 1000 * 1e6, deadline: block.timestamp + 1 hours, v: 27, r: bytes32(0), s: bytes32(0)
        });

        vm.prank(notExecutor);
        vm.expectRevert(IkPaymaster.kPaymaster_NotTrustedExecutor.selector);
        paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permit, "", 100 * 1e6);
    }

    function test_nonces() public view {
        assertEq(paymaster.nonces(user), 0);
    }

    function test_incrementNonce() public {
        assertEq(paymaster.nonces(user), 0);

        vm.prank(user);
        paymaster.incrementNonce();
        assertEq(paymaster.nonces(user), 1);

        vm.prank(user);
        paymaster.incrementNonce();
        assertEq(paymaster.nonces(user), 2);
    }

    function test_incrementNonce_invalidatesSignature() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 10 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(dnVault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: user
        });
        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kUSD), user, address(paymaster), stakeAmount, deadline, kUSD.nonces(user), USER_PRIVATE_KEY
        );

        // User increments nonce to invalidate the signed request
        vm.prank(user);
        paymaster.incrementNonce();

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_InvalidNonce.selector);
        paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permit, requestSig, fee);
    }

    function test_incrementNonce_emitsEvent() public {
        vm.prank(user);
        vm.expectEmit(true, false, false, true);
        emit IkPaymaster.NonceIncremented(user, 1);
        paymaster.incrementNonce();
    }

    function test_domainSeparator() public view {
        bytes32 separator = paymaster.DOMAIN_SEPARATOR();
        assertNotEq(separator, bytes32(0));
    }

    function test_setTreasury() public {
        address newTreasury = makeAddr("newTreasury");
        vm.prank(users.owner);
        paymaster.setTreasury(newTreasury);
        assertEq(paymaster.treasury(), newTreasury);
    }

    function test_revert_setTreasury_zeroAddress() public {
        vm.prank(users.owner);
        vm.expectRevert(IkPaymaster.kPaymaster_ZeroAddress.selector);
        paymaster.setTreasury(address(0));
    }

    function test_transferOwnership() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(users.owner);
        paymaster.transferOwnership(newOwner);
        assertEq(paymaster.owner(), newOwner);
    }

    function test_rescueTokens() public {
        // Send kUSD to paymaster
        vm.prank(user);
        kUSD.transfer(address(paymaster), 1000 * 1e6);

        address recipient = makeAddr("recipient");

        vm.prank(users.owner);
        paymaster.rescueTokens(address(kUSD), recipient, 1000 * 1e6);

        assertEq(kUSD.balanceOf(recipient), 1000 * 1e6);
    }

    /* //////////////////////////////////////////////////////////////
                          AUTOCLAIM TESTS
    //////////////////////////////////////////////////////////////*/

    function test_executeRequestStakeWithAutoclaimWithPermit() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(kUSD), user, address(paymaster), stakeAmount, deadline, kUSD.nonces(user), USER_PRIVATE_KEY
        );

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(dnVault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        uint256 userBalanceBefore = kUSD.balanceOf(user);
        uint256 treasuryBalanceBefore = kUSD.balanceOf(users.treasury);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permitSig, requestSig, fee);

        assertNotEq(requestId, bytes32(0));
        assertEq(kUSD.balanceOf(user), userBalanceBefore - stakeAmount);
        assertEq(kUSD.balanceOf(users.treasury), treasuryBalanceBefore + fee);
        assertTrue(paymaster.canAutoclaim(requestId));
        assertEq(paymaster.nonces(user), 1);
    }

    function test_executeRequestStakeWithAutoclaim_withoutPermit() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(user);
        kUSD.approve(address(paymaster), stakeAmount);

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(dnVault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        uint256 treasuryBalanceBefore = kUSD.balanceOf(users.treasury);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestStakeWithAutoclaim(request, requestSig, fee);

        assertNotEq(requestId, bytes32(0));
        assertEq(kUSD.balanceOf(users.treasury), treasuryBalanceBefore + fee);
        assertTrue(paymaster.canAutoclaim(requestId));
    }

    function test_executeAutoclaimStakedShares() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;

        bytes32 requestId = _stakeWithAutoclaimAndSettle(stakeAmount, fee);

        assertTrue(paymaster.canAutoclaim(requestId));

        uint256 userStkBalanceBefore = dnVault.balanceOf(user);

        vm.prank(executor);
        paymaster.executeAutoclaimStakedShares(requestId);

        assertGt(dnVault.balanceOf(user), userStkBalanceBefore);
        assertFalse(paymaster.canAutoclaim(requestId));
    }

    function test_executeRequestUnstakeWithAutoclaimWithPermit() public {
        uint96 unstakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(dnVault),
            user,
            address(paymaster),
            unstakeAmount,
            deadline,
            IERC20Permit(address(dnVault)).nonces(user),
            USER_PRIVATE_KEY
        );

        IkPaymaster.UnstakeWithAutoclaimRequest memory request = IkPaymaster.UnstakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(dnVault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            stkTokenAmount: unstakeAmount
        });

        bytes memory requestSig = _createUnstakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        uint256 userStkBalanceBefore = dnVault.balanceOf(user);
        uint256 treasuryBalanceBefore = dnVault.balanceOf(users.treasury);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestUnstakeWithAutoclaimWithPermit(request, permitSig, requestSig, fee);

        assertNotEq(requestId, bytes32(0));
        assertEq(dnVault.balanceOf(user), userStkBalanceBefore - unstakeAmount);
        assertEq(dnVault.balanceOf(users.treasury), treasuryBalanceBefore + fee);
        assertTrue(paymaster.canAutoclaim(requestId));
    }

    function test_executeAutoclaimUnstakedAssets() public {
        uint96 unstakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;

        bytes32 requestId = _unstakeWithAutoclaimAndSettle(unstakeAmount, fee);

        assertTrue(paymaster.canAutoclaim(requestId));

        uint256 userKTokenBalanceBefore = kUSD.balanceOf(user);

        vm.prank(executor);
        paymaster.executeAutoclaimUnstakedAssets(requestId);

        assertGt(kUSD.balanceOf(user), userKTokenBalanceBefore);
        assertFalse(paymaster.canAutoclaim(requestId));
    }

    function test_revert_autoclaimNotRegistered() public {
        bytes32 fakeRequestId = keccak256("fake");

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_AutoclaimNotRegistered.selector);
        paymaster.executeAutoclaimStakedShares(fakeRequestId);
    }

    function test_revert_autoclaimAlreadyExecuted() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;

        bytes32 requestId = _stakeWithAutoclaimAndSettle(stakeAmount, fee);

        vm.prank(executor);
        paymaster.executeAutoclaimStakedShares(requestId);

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_AutoclaimAlreadyExecuted.selector);
        paymaster.executeAutoclaimStakedShares(requestId);
    }

    function test_getAutoclaimAuth() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(user);
        kUSD.approve(address(paymaster), stakeAmount);

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(dnVault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestStakeWithAutoclaim(request, requestSig, fee);

        IkPaymaster.AutoclaimAuth memory auth = paymaster.getAutoclaimAuth(requestId);
        assertEq(auth.vault, address(dnVault));
        assertTrue(auth.isStake);
        assertFalse(auth.executed);
    }

    function test_executeAutoclaimStakedSharesBatch() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;

        bytes32[] memory requestIds = new bytes32[](3);

        for (uint256 i = 0; i < 3; i++) {
            requestIds[i] = _stakeWithAutoclaimAndSettle(stakeAmount, fee);
            assertTrue(paymaster.canAutoclaim(requestIds[i]));
        }

        uint256 userStkBalanceBefore = dnVault.balanceOf(user);

        vm.prank(executor);
        paymaster.executeAutoclaimStakedSharesBatch(requestIds);

        for (uint256 i = 0; i < 3; i++) {
            assertFalse(paymaster.canAutoclaim(requestIds[i]));
        }
        assertGt(dnVault.balanceOf(user), userStkBalanceBefore);
    }

    function test_executeAutoclaimUnstakedAssetsBatch() public {
        uint96 unstakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;

        bytes32[] memory requestIds = new bytes32[](3);

        for (uint256 i = 0; i < 3; i++) {
            requestIds[i] = _unstakeWithAutoclaimAndSettle(unstakeAmount, fee);
            assertTrue(paymaster.canAutoclaim(requestIds[i]));
        }

        uint256 userKTokenBalanceBefore = kUSD.balanceOf(user);

        vm.prank(executor);
        paymaster.executeAutoclaimUnstakedAssetsBatch(requestIds);

        for (uint256 i = 0; i < 3; i++) {
            assertFalse(paymaster.canAutoclaim(requestIds[i]));
        }
        assertGt(kUSD.balanceOf(user), userKTokenBalanceBefore);
    }

    function test_batchAutoclaim_skipsInvalidRequests() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;

        bytes32 validRequestId = _stakeWithAutoclaimAndSettle(stakeAmount, fee);

        bytes32[] memory requestIds = new bytes32[](3);
        requestIds[0] = keccak256("fake1");
        requestIds[1] = validRequestId;
        requestIds[2] = keccak256("fake2");

        vm.prank(executor);
        paymaster.executeAutoclaimStakedSharesBatch(requestIds);

        assertFalse(paymaster.canAutoclaim(validRequestId));
    }

    function test_executeRequestStakeWithAutoclaimBatch() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.StakeWithAutoclaimRequest[] memory requests = new IkPaymaster.StakeWithAutoclaimRequest[](2);
        bytes[] memory sigs = new bytes[](2);
        uint96[] memory fees = new uint96[](2);

        vm.prank(user);
        kUSD.approve(address(paymaster), stakeAmount * 2);

        for (uint256 i = 0; i < 2; i++) {
            requests[i] = IkPaymaster.StakeWithAutoclaimRequest({
                user: user,
                nonce: uint96(i),
                vault: address(dnVault),
                deadline: uint96(deadline),
                recipient: user,
                maxFee: DEFAULT_MAX_FEE,
                kTokenAmount: stakeAmount
            });

            sigs[i] = _createStakeWithAutoclaimRequestSignature(requests[i], USER_PRIVATE_KEY);
            fees[i] = fee;
        }

        vm.prank(executor);
        bytes32[] memory requestIds = paymaster.executeRequestStakeWithAutoclaimBatch(requests, sigs, fees);

        assertEq(requestIds.length, 2);
        for (uint256 i = 0; i < 2; i++) {
            assertTrue(paymaster.canAutoclaim(requestIds[i]));
        }
        assertEq(paymaster.nonces(user), 2);
    }

    function test_executeRequestUnstakeWithAutoclaimBatch() public {
        uint96 unstakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.UnstakeWithAutoclaimRequest[] memory requests = new IkPaymaster.UnstakeWithAutoclaimRequest[](2);
        bytes[] memory sigs = new bytes[](2);
        uint96[] memory fees = new uint96[](2);

        vm.prank(user);
        dnVault.approve(address(paymaster), unstakeAmount * 2);

        for (uint256 i = 0; i < 2; i++) {
            requests[i] = IkPaymaster.UnstakeWithAutoclaimRequest({
                user: user,
                nonce: uint96(i),
                vault: address(dnVault),
                deadline: uint96(deadline),
                recipient: user,
                maxFee: DEFAULT_MAX_FEE,
                stkTokenAmount: unstakeAmount
            });

            sigs[i] = _createUnstakeWithAutoclaimRequestSignature(requests[i], USER_PRIVATE_KEY);
            fees[i] = fee;
        }

        vm.prank(executor);
        bytes32[] memory requestIds = paymaster.executeRequestUnstakeWithAutoclaimBatch(requests, sigs, fees);

        assertEq(requestIds.length, 2);
        for (uint256 i = 0; i < 2; i++) {
            assertTrue(paymaster.canAutoclaim(requestIds[i]));
        }
        assertEq(paymaster.nonces(user), 2);
    }

    /* //////////////////////////////////////////////////////////////
                          ERROR CASE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_revert_feeExceedsMax() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 maxFee = 10 * 1e6;
        uint96 fee = 50 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kUSD), user, address(paymaster), stakeAmount, deadline, kUSD.nonces(user), USER_PRIVATE_KEY
        );

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(dnVault),
            deadline: uint96(deadline),
            maxFee: maxFee,
            kTokenAmount: stakeAmount,
            recipient: user
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_FeeExceedsMax.selector);
        paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permit, requestSig, fee);
    }

    function test_revert_insufficientAmountForFee() public {
        uint96 stakeAmount = 100 * 1e6;
        uint96 fee = 200 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kUSD), user, address(paymaster), stakeAmount, deadline, kUSD.nonces(user), USER_PRIVATE_KEY
        );

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(dnVault),
            deadline: uint96(deadline),
            maxFee: fee,
            kTokenAmount: stakeAmount,
            recipient: user
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_InsufficientAmountForFee.selector);
        paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permit, requestSig, fee);
    }

    function test_revert_requestExpired() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 10 * 1e6;
        uint256 deadline = block.timestamp - 1;
        uint256 permitDeadline = block.timestamp + 1 hours;

        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kUSD), user, address(paymaster), stakeAmount, permitDeadline, kUSD.nonces(user), USER_PRIVATE_KEY
        );

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(dnVault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: user
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_RequestExpired.selector);
        paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permit, requestSig, fee);
    }

    function test_revert_invalidNonce() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 10 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kUSD), user, address(paymaster), stakeAmount, deadline, kUSD.nonces(user), USER_PRIVATE_KEY
        );

        IkPaymaster.StakeWithAutoclaimRequest memory request = IkPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 999,
            vault: address(dnVault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: user
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_InvalidNonce.selector);
        paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permit, requestSig, fee);
    }
}
