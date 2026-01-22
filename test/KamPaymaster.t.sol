// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { KamPaymaster } from "../src/KamPaymaster.sol";
import { IKamPaymaster } from "../src/interfaces/IKamPaymaster.sol";
import { Test } from "forge-std/Test.sol";

contract MockERC20Permit {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    bytes32 public DOMAIN_SEPARATOR;

    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(_name)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        external
    {
        require(deadline >= block.timestamp, "permit expired");

        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "invalid signature");

        allowance[owner][spender] = value;
    }
}

contract MockKStakingVault is MockERC20Permit {
    address public kToken;
    uint256 public sharePrice = 1e6;
    uint256 private _requestCounter;

    // Storage for stake/unstake requests (for autoclaim tests)
    struct StakeRequestData {
        address user;
        uint128 kTokenAmount;
        address recipient;
    }

    struct UnstakeRequestData {
        address user;
        uint128 stkTokenAmount;
        address recipient;
    }

    mapping(bytes32 => StakeRequestData) public stakeRequests;
    mapping(bytes32 => UnstakeRequestData) public unstakeRequests;

    constructor(address _kToken) MockERC20Permit("Staked kUSDC", "stkUSDC", 6) {
        kToken = _kToken;
    }

    // asset() returns kToken in kStakingVault
    function asset() external view returns (address) {
        return kToken;
    }

    function setSharePrice(uint256 _sharePrice) external {
        sharePrice = _sharePrice;
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        return assets * 1e6 / sharePrice;
    }

    function convertToAssets(uint256 shares) external view returns (uint256) {
        return shares * sharePrice / 1e6;
    }

    function requestStake(address owner, address to, uint256 amount) external payable returns (bytes32) {
        address sender = _msgSender();
        // ERC2771: paymaster forwards call with itself as msg.sender, owner param specifies request owner
        MockERC20Permit(kToken).transferFrom(sender, address(this), amount);
        balanceOf[to] += amount;
        totalSupply += amount;

        bytes32 requestId = keccak256(abi.encode(owner, to, amount, block.timestamp, ++_requestCounter));
        stakeRequests[requestId] = StakeRequestData({ user: owner, kTokenAmount: uint128(amount), recipient: to });
        return requestId;
    }

    function requestUnstake(address owner, address to, uint256 amount) external payable returns (bytes32) {
        // ERC2771: paymaster forwards call with itself as msg.sender, owner param specifies request owner
        MockERC20Permit(address(this)).transferFrom(msg.sender, address(this), amount);

        bytes32 requestId = keccak256(abi.encode(owner, to, amount, block.timestamp, ++_requestCounter));
        unstakeRequests[requestId] = UnstakeRequestData({ user: owner, stkTokenAmount: uint128(amount), recipient: to });
        return requestId;
    }

    function claimStakedShares(bytes32 requestId) external payable {
        address user = _msgSender();
        balanceOf[user] += 1000 * 1e6;
        totalSupply += 1000 * 1e6;
        requestId;
    }

    function claimUnstakedAssets(bytes32 requestId) external payable {
        address user = _msgSender();
        MockERC20Permit(kToken).mint(user, 1000 * 1e6);
        requestId;
    }

    // IVaultReader functions for autoclaim
    function getStakeRequest(bytes32 requestId)
        external
        view
        returns (
            address user,
            uint128 kTokenAmount,
            address recipient,
            bytes32 batchId,
            uint64 requestTimestamp,
            uint8 status
        )
    {
        StakeRequestData storage req = stakeRequests[requestId];
        return (req.user, req.kTokenAmount, req.recipient, bytes32(0), 0, 0);
    }

    function getUnstakeRequest(bytes32 requestId)
        external
        view
        returns (
            address user,
            uint128 stkTokenAmount,
            address recipient,
            bytes32 batchId,
            uint64 requestTimestamp,
            uint8 status
        )
    {
        UnstakeRequestData storage req = unstakeRequests[requestId];
        return (req.user, req.stkTokenAmount, req.recipient, bytes32(0), 0, 0);
    }

    function _msgSender() internal view returns (address) {
        if (msg.data.length >= 20) {
            address sender;
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
            if (msg.sender != sender) {
                return sender;
            }
        }
        return msg.sender;
    }
}

contract MockRegistry {
    mapping(address => bool) private _vaults;

    function setVault(address vault, bool isValid) external {
        _vaults[vault] = isValid;
    }

    function isVault(address vault) external view returns (bool) {
        return _vaults[vault];
    }
}

contract KamPaymasterTest is Test {
    KamPaymaster public paymaster;
    MockERC20Permit public kToken;
    MockERC20Permit public underlyingAsset;
    MockKStakingVault public vault;
    MockRegistry public mockRegistry;

    address public owner;
    address public treasury;
    address public user;
    uint256 public userPrivateKey;
    address public executor;

    uint96 constant DEFAULT_MAX_FEE = 100 * 1e6; // Default max fee for tests

    function setUp() public {
        owner = makeAddr("owner");
        treasury = makeAddr("treasury");
        executor = makeAddr("executor");
        userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        user = vm.addr(userPrivateKey);

        underlyingAsset = new MockERC20Permit("USD Coin", "USDC", 6);
        kToken = new MockERC20Permit("KAM USDC", "kUSDC", 6);
        vault = new MockKStakingVault(address(kToken));

        // Deploy mock registry and register the vault
        mockRegistry = new MockRegistry();
        mockRegistry.setVault(address(vault), true);

        vm.prank(owner);
        paymaster = new KamPaymaster(owner, treasury, address(mockRegistry));

        vm.prank(owner);
        paymaster.setTrustedExecutor(executor, true);

        kToken.mint(user, 1_000_000 * 1e6);
        vault.mint(user, 1_000_000 * 1e6);
    }

    function test_constructor() public view {
        assertEq(paymaster.owner(), owner);
        assertEq(paymaster.treasury(), treasury);
        assertTrue(paymaster.isTrustedExecutor(owner));
    }

    function test_setTrustedExecutor() public {
        address newExecutor = makeAddr("newExecutor");

        vm.prank(owner);
        paymaster.setTrustedExecutor(newExecutor, true);
        assertTrue(paymaster.isTrustedExecutor(newExecutor));

        vm.prank(owner);
        paymaster.setTrustedExecutor(newExecutor, false);
        assertFalse(paymaster.isTrustedExecutor(newExecutor));
    }

    function test_revert_notTrustedExecutor() public {
        address notExecutor = makeAddr("notExecutor");

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(block.timestamp + 1 hours),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: 1000 * 1e6,
            recipient: user
        });

        // Single permit to paymaster for full amount
        IKamPaymaster.PermitSignature memory permit = IKamPaymaster.PermitSignature({
            value: 1000 * 1e6, deadline: block.timestamp + 1 hours, v: 27, r: bytes32(0), s: bytes32(0)
        });

        vm.prank(notExecutor);
        vm.expectRevert(IKamPaymaster.NotTrustedExecutor.selector);
        paymaster.executeRequestStakeWithPermit(request, permit, "", 100 * 1e6);
    }

    function test_nonces() public view {
        assertEq(paymaster.nonces(user), 0);
    }

    function test_domainSeparator() public view {
        bytes32 separator = paymaster.DOMAIN_SEPARATOR();
        assertNotEq(separator, bytes32(0));
    }

    function test_setTreasury() public {
        address newTreasury = makeAddr("newTreasury");
        vm.prank(owner);
        paymaster.setTreasury(newTreasury);
        assertEq(paymaster.treasury(), newTreasury);
    }

    function test_revert_setTreasury_zeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(IKamPaymaster.ZeroAddress.selector);
        paymaster.setTreasury(address(0));
    }

    function test_transferOwnership() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(owner);
        paymaster.transferOwnership(newOwner);
        assertEq(paymaster.owner(), newOwner);
    }

    function test_rescueTokens() public {
        kToken.mint(address(paymaster), 1000 * 1e6);
        address recipient = makeAddr("recipient");

        vm.prank(owner);
        paymaster.rescueTokens(address(kToken), recipient, 1000 * 1e6);

        assertEq(kToken.balanceOf(recipient), 1000 * 1e6);
    }

    function test_executeRequestStakeWithPermit() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 10 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        // Create single permit signature for paymaster (to pull full amount)
        IKamPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kToken), user, address(paymaster), stakeAmount, deadline, kToken.nonces(user), userPrivateKey
        );

        // Create stake request
        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: user
        });

        // Create request signature
        bytes memory requestSig = _createStakeRequestSignature(request, userPrivateKey);

        uint256 treasuryBalanceBefore = kToken.balanceOf(treasury);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestStakeWithPermit(request, permit, requestSig, fee);

        assertNotEq(requestId, bytes32(0));
        assertEq(kToken.balanceOf(treasury), treasuryBalanceBefore + fee);
        assertEq(paymaster.nonces(user), 1);
    }

    function test_executeStake_withoutPermit() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 10 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        // User approves paymaster for full amount (single permit model)
        vm.prank(user);
        kToken.approve(address(paymaster), stakeAmount);

        // Create stake request
        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: user
        });

        // Create request signature
        bytes memory requestSig = _createStakeRequestSignature(request, userPrivateKey);

        uint256 treasuryBalanceBefore = kToken.balanceOf(treasury);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestStake(request, requestSig, fee);

        assertNotEq(requestId, bytes32(0));
        assertEq(kToken.balanceOf(treasury), treasuryBalanceBefore + fee);
        assertEq(paymaster.nonces(user), 1);
    }

    function test_executeRequestUnstakeWithPermit() public {
        uint96 unstakeAmount = 1000 * 1e6;
        uint96 fee = 10 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        // Create permit signature for stkToken (vault) - single permit model: permit full amount
        IKamPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(vault), user, address(paymaster), unstakeAmount, deadline, vault.nonces(user), userPrivateKey
        );

        // Create unstake request
        IKamPaymaster.UnstakeRequest memory request = IKamPaymaster.UnstakeRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            stkTokenAmount: unstakeAmount,
            recipient: user
        });

        // Create request signature
        bytes memory requestSig = _createUnstakeRequestSignature(request, userPrivateKey);

        uint256 treasuryBalanceBefore = vault.balanceOf(treasury);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestUnstakeWithPermit(request, permitSig, requestSig, fee);

        assertNotEq(requestId, bytes32(0));
        assertEq(vault.balanceOf(treasury), treasuryBalanceBefore + fee);
        assertEq(paymaster.nonces(user), 1);
    }

    function test_executeUnstake_withoutPermit() public {
        uint96 unstakeAmount = 1000 * 1e6;
        uint96 fee = 10 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        // User approves paymaster directly - single permit model: approve full amount
        vm.prank(user);
        vault.approve(address(paymaster), unstakeAmount);

        // Create unstake request
        IKamPaymaster.UnstakeRequest memory request = IKamPaymaster.UnstakeRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            stkTokenAmount: unstakeAmount,
            recipient: user
        });

        // Create request signature
        bytes memory requestSig = _createUnstakeRequestSignature(request, userPrivateKey);

        uint256 treasuryBalanceBefore = vault.balanceOf(treasury);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestUnstake(request, requestSig, fee);

        assertNotEq(requestId, bytes32(0));
        assertEq(vault.balanceOf(treasury), treasuryBalanceBefore + fee);
        assertEq(paymaster.nonces(user), 1);
    }

    function test_executeClaimStakedSharesWithPermit() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint96 fee = 5 * 1e6;
        bytes32 mockRequestId = keccak256("mockRequestId");

        // Create permit signature for stkToken (for fee payment)
        IKamPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(vault), user, address(paymaster), fee, deadline, vault.nonces(user), userPrivateKey
        );

        // Create claim request
        IKamPaymaster.ClaimRequest memory request = IKamPaymaster.ClaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            requestId: mockRequestId
        });

        // Create request signature
        bytes memory requestSig = _createClaimRequestSignature(request, userPrivateKey);

        uint256 userBalanceBefore = vault.balanceOf(user);
        uint256 treasuryBalanceBefore = vault.balanceOf(treasury);

        vm.prank(executor);
        paymaster.executeClaimStakedSharesWithPermit(request, permitSig, requestSig, fee);

        // User receives shares minus fee
        assertGt(vault.balanceOf(user), userBalanceBefore);
        assertEq(vault.balanceOf(treasury), treasuryBalanceBefore + fee);
        assertEq(paymaster.nonces(user), 1);
    }

    function test_executeClaimStakedShares_withoutPermit() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint96 fee = 5 * 1e6;
        bytes32 mockRequestId = keccak256("mockRequestId");

        // User approves paymaster for fee
        vm.prank(user);
        vault.approve(address(paymaster), fee);

        // Create claim request
        IKamPaymaster.ClaimRequest memory request = IKamPaymaster.ClaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            requestId: mockRequestId
        });

        // Create request signature
        bytes memory requestSig = _createClaimRequestSignature(request, userPrivateKey);

        uint256 userBalanceBefore = vault.balanceOf(user);
        uint256 treasuryBalanceBefore = vault.balanceOf(treasury);

        vm.prank(executor);
        paymaster.executeClaimStakedShares(request, requestSig, fee);

        assertGt(vault.balanceOf(user), userBalanceBefore);
        assertEq(vault.balanceOf(treasury), treasuryBalanceBefore + fee);
        assertEq(paymaster.nonces(user), 1);
    }

    function test_executeClaimUnstakedAssetsWithPermit() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint96 fee = 5 * 1e6;
        bytes32 mockRequestId = keccak256("mockRequestId");

        // Create permit signature for kToken (for fee payment)
        IKamPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(kToken), user, address(paymaster), fee, deadline, kToken.nonces(user), userPrivateKey
        );

        // Create claim request
        IKamPaymaster.ClaimRequest memory request = IKamPaymaster.ClaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            requestId: mockRequestId
        });

        // Create request signature
        bytes memory requestSig = _createClaimRequestSignature(request, userPrivateKey);

        uint256 userBalanceBefore = kToken.balanceOf(user);
        uint256 treasuryBalanceBefore = kToken.balanceOf(treasury);

        vm.prank(executor);
        paymaster.executeClaimUnstakedAssetsWithPermit(request, permitSig, requestSig, fee);

        assertGt(kToken.balanceOf(user), userBalanceBefore);
        assertEq(kToken.balanceOf(treasury), treasuryBalanceBefore + fee);
        assertEq(paymaster.nonces(user), 1);
    }

    function test_executeClaimUnstakedAssets_withoutPermit() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint96 fee = 5 * 1e6;
        bytes32 mockRequestId = keccak256("mockRequestId");

        // User approves paymaster for fee
        vm.prank(user);
        kToken.approve(address(paymaster), fee);

        // Create claim request
        IKamPaymaster.ClaimRequest memory request = IKamPaymaster.ClaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            requestId: mockRequestId
        });

        // Create request signature
        bytes memory requestSig = _createClaimRequestSignature(request, userPrivateKey);

        uint256 userBalanceBefore = kToken.balanceOf(user);
        uint256 treasuryBalanceBefore = kToken.balanceOf(treasury);

        vm.prank(executor);
        paymaster.executeClaimUnstakedAssets(request, requestSig, fee);

        assertGt(kToken.balanceOf(user), userBalanceBefore);
        assertEq(kToken.balanceOf(treasury), treasuryBalanceBefore + fee);
        assertEq(paymaster.nonces(user), 1);
    }

    function test_executeClaimWithZeroFee() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint96 fee = 0;
        bytes32 mockRequestId = keccak256("mockRequestId");

        // Create claim request
        IKamPaymaster.ClaimRequest memory request = IKamPaymaster.ClaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: 0, // maxFee of 0 allows 0 fee
            requestId: mockRequestId
        });

        // Create request signature
        bytes memory requestSig = _createClaimRequestSignature(request, userPrivateKey);

        uint256 treasuryBalanceBefore = vault.balanceOf(treasury);

        vm.prank(executor);
        paymaster.executeClaimStakedShares(request, requestSig, fee);

        // No fee collected
        assertEq(vault.balanceOf(treasury), treasuryBalanceBefore);
        assertEq(paymaster.nonces(user), 1);
    }

    function test_revert_feeExceedsMax() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 maxFee = 10 * 1e6;
        uint96 fee = 50 * 1e6; // Fee exceeds maxFee
        uint256 deadline = block.timestamp + 1 hours;

        // Single permit for full amount to paymaster
        IKamPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kToken), user, address(paymaster), stakeAmount, deadline, kToken.nonces(user), userPrivateKey
        );

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: maxFee,
            kTokenAmount: stakeAmount,
            recipient: user
        });

        bytes memory requestSig = _createStakeRequestSignature(request, userPrivateKey);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.FeeExceedsMax.selector);
        paymaster.executeRequestStakeWithPermit(request, permit, requestSig, fee);
    }

    function test_revert_insufficientAmountForFee() public {
        uint96 stakeAmount = 100 * 1e6;
        uint96 fee = 200 * 1e6; // Fee greater than amount
        uint256 deadline = block.timestamp + 1 hours;

        // Single permit for full amount to paymaster
        IKamPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kToken), user, address(paymaster), stakeAmount, deadline, kToken.nonces(user), userPrivateKey
        );

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: fee, // maxFee set to fee to pass maxFee check
            kTokenAmount: stakeAmount,
            recipient: user
        });

        bytes memory requestSig = _createStakeRequestSignature(request, userPrivateKey);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.InsufficientAmountForFee.selector);
        paymaster.executeRequestStakeWithPermit(request, permit, requestSig, fee);
    }

    function test_revert_requestExpired() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 10 * 1e6;
        uint256 deadline = block.timestamp - 1; // Already expired
        uint256 permitDeadline = block.timestamp + 1 hours;

        // Single permit for full amount to paymaster
        IKamPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kToken), user, address(paymaster), stakeAmount, permitDeadline, kToken.nonces(user), userPrivateKey
        );

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: user
        });

        bytes memory requestSig = _createStakeRequestSignature(request, userPrivateKey);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.RequestExpired.selector);
        paymaster.executeRequestStakeWithPermit(request, permit, requestSig, fee);
    }

    function test_revert_invalidNonce() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 10 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        // Single permit for full amount to paymaster
        IKamPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kToken), user, address(paymaster), stakeAmount, deadline, kToken.nonces(user), userPrivateKey
        );

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: user,
            nonce: 999, // Wrong nonce
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: user
        });

        bytes memory requestSig = _createStakeRequestSignature(request, userPrivateKey);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.InvalidNonce.selector);
        paymaster.executeRequestStakeWithPermit(request, permit, requestSig, fee);
    }

    /*//////////////////////////////////////////////////////////////
                          AUTOCLAIM TESTS
    //////////////////////////////////////////////////////////////*/

    function test_executeRequestStakeWithAutoclaimWithPermit() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6; // Combined fee covers both request + claim
        uint256 deadline = block.timestamp + 1 hours;

        // Create permit signature for kToken - full amount (stakeAmount includes fee)
        IKamPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(kToken), user, address(paymaster), stakeAmount, deadline, kToken.nonces(user), userPrivateKey
        );

        // Create stake with autoclaim request
        IKamPaymaster.StakeWithAutoclaimRequest memory request = IKamPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, userPrivateKey);

        uint256 userBalanceBefore = kToken.balanceOf(user);
        uint256 treasuryBalanceBefore = kToken.balanceOf(treasury);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestStakeWithAutoclaimWithPermit(request, permitSig, requestSig, fee);

        assertNotEq(requestId, bytes32(0));
        // User paid full stakeAmount
        assertEq(kToken.balanceOf(user), userBalanceBefore - stakeAmount);
        // Treasury received fee (covers both request + claim)
        assertEq(kToken.balanceOf(treasury), treasuryBalanceBefore + fee);
        // Autoclaim is registered
        assertTrue(paymaster.canAutoclaim(requestId));
        assertEq(paymaster.nonces(user), 1);
    }

    function test_executeRequestStakeWithAutoclaim_withoutPermit() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6; // Combined fee covers both request + claim
        uint256 deadline = block.timestamp + 1 hours;

        // User approves paymaster directly
        vm.prank(user);
        kToken.approve(address(paymaster), stakeAmount);

        IKamPaymaster.StakeWithAutoclaimRequest memory request = IKamPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, userPrivateKey);

        uint256 treasuryBalanceBefore = kToken.balanceOf(treasury);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestStakeWithAutoclaim(request, requestSig, fee);

        assertNotEq(requestId, bytes32(0));
        // Treasury received fee (covers both request + claim)
        assertEq(kToken.balanceOf(treasury), treasuryBalanceBefore + fee);
        assertTrue(paymaster.canAutoclaim(requestId));
    }

    function test_executeAutoclaimStakedShares() public {
        // First, create a stake with autoclaim request
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6; // Combined fee covers both request + claim
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(user);
        kToken.approve(address(paymaster), stakeAmount);

        IKamPaymaster.StakeWithAutoclaimRequest memory request = IKamPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, userPrivateKey);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestStakeWithAutoclaim(request, requestSig, fee);

        // Verify autoclaim is registered
        assertTrue(paymaster.canAutoclaim(requestId));

        // Now execute autoclaim (no fee parameter - fee was paid upfront)
        uint256 userStkBalanceBefore = vault.balanceOf(user);

        vm.prank(executor);
        paymaster.executeAutoclaimStakedShares(requestId);

        // Autoclaim executed - user received stkTokens from mock
        assertGt(vault.balanceOf(user), userStkBalanceBefore);
        // Autoclaim can no longer be executed
        assertFalse(paymaster.canAutoclaim(requestId));
    }

    function test_executeRequestUnstakeWithAutoclaimWithPermit() public {
        uint96 unstakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6; // Combined fee covers both request + claim
        uint256 deadline = block.timestamp + 1 hours;

        // Create permit signature for stkToken (vault) - full amount
        IKamPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(vault), user, address(paymaster), unstakeAmount, deadline, vault.nonces(user), userPrivateKey
        );

        IKamPaymaster.UnstakeWithAutoclaimRequest memory request = IKamPaymaster.UnstakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            stkTokenAmount: unstakeAmount
        });

        bytes memory requestSig = _createUnstakeWithAutoclaimRequestSignature(request, userPrivateKey);

        uint256 userStkBalanceBefore = vault.balanceOf(user);
        uint256 treasuryBalanceBefore = vault.balanceOf(treasury);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestUnstakeWithAutoclaimWithPermit(request, permitSig, requestSig, fee);

        assertNotEq(requestId, bytes32(0));
        // User paid full unstakeAmount
        assertEq(vault.balanceOf(user), userStkBalanceBefore - unstakeAmount);
        // Treasury received fee (covers both request + claim) in stkTokens
        assertEq(vault.balanceOf(treasury), treasuryBalanceBefore + fee);
        assertTrue(paymaster.canAutoclaim(requestId));
    }

    function test_executeAutoclaimUnstakedAssets() public {
        // First, create an unstake with autoclaim request
        uint96 unstakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6; // Combined fee covers both request + claim
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(user);
        vault.approve(address(paymaster), unstakeAmount);

        IKamPaymaster.UnstakeWithAutoclaimRequest memory request = IKamPaymaster.UnstakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            stkTokenAmount: unstakeAmount
        });

        bytes memory requestSig = _createUnstakeWithAutoclaimRequestSignature(request, userPrivateKey);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestUnstakeWithAutoclaim(request, requestSig, fee);

        assertTrue(paymaster.canAutoclaim(requestId));

        // Now execute autoclaim
        uint256 userKTokenBalanceBefore = kToken.balanceOf(user);

        vm.prank(executor);
        paymaster.executeAutoclaimUnstakedAssets(requestId);

        // User received kTokens from mock
        assertGt(kToken.balanceOf(user), userKTokenBalanceBefore);
        assertFalse(paymaster.canAutoclaim(requestId));
    }

    function test_revert_autoclaimNotRegistered() public {
        bytes32 fakeRequestId = keccak256("fake");

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.AutoclaimNotRegistered.selector);
        paymaster.executeAutoclaimStakedShares(fakeRequestId);
    }

    function test_revert_autoclaimAlreadyExecuted() public {
        // Create and execute autoclaim
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6; // Combined fee covers both request + claim
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(user);
        kToken.approve(address(paymaster), stakeAmount);

        IKamPaymaster.StakeWithAutoclaimRequest memory request = IKamPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, userPrivateKey);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestStakeWithAutoclaim(request, requestSig, fee);

        // Execute autoclaim first time
        vm.prank(executor);
        paymaster.executeAutoclaimStakedShares(requestId);

        // Try to execute again - should fail
        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.AutoclaimAlreadyExecuted.selector);
        paymaster.executeAutoclaimStakedShares(requestId);
    }

    function test_getAutoclaimAuth() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6; // Combined fee covers both request + claim
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(user);
        kToken.approve(address(paymaster), stakeAmount);

        IKamPaymaster.StakeWithAutoclaimRequest memory request = IKamPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, userPrivateKey);

        vm.prank(executor);
        bytes32 requestId = paymaster.executeRequestStakeWithAutoclaim(request, requestSig, fee);

        IKamPaymaster.AutoclaimAuth memory auth = paymaster.getAutoclaimAuth(requestId);
        assertEq(auth.vault, address(vault));
        assertTrue(auth.isStake);
        assertFalse(auth.executed);
    }

    function test_executeAutoclaimStakedSharesBatch() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        // Create multiple stake requests with autoclaim
        bytes32[] memory requestIds = new bytes32[](3);

        for (uint256 i = 0; i < 3; i++) {
            vm.prank(user);
            kToken.approve(address(paymaster), stakeAmount);

            IKamPaymaster.StakeWithAutoclaimRequest memory request = IKamPaymaster.StakeWithAutoclaimRequest({
                user: user,
                nonce: uint96(i),
                vault: address(vault),
                deadline: uint96(deadline),
                recipient: user,
                maxFee: DEFAULT_MAX_FEE,
                kTokenAmount: stakeAmount
            });

            bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, userPrivateKey);

            vm.prank(executor);
            requestIds[i] = paymaster.executeRequestStakeWithAutoclaim(request, requestSig, fee);
            assertTrue(paymaster.canAutoclaim(requestIds[i]));
        }

        // Execute batch autoclaim
        uint256 userStkBalanceBefore = vault.balanceOf(user);

        vm.prank(executor);
        paymaster.executeAutoclaimStakedSharesBatch(requestIds);

        // Verify all autoclaims were executed
        for (uint256 i = 0; i < 3; i++) {
            assertFalse(paymaster.canAutoclaim(requestIds[i]));
        }
        // User received stkTokens from all claims
        assertGt(vault.balanceOf(user), userStkBalanceBefore);
    }

    function test_executeAutoclaimUnstakedAssetsBatch() public {
        uint96 unstakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        // Create multiple unstake requests with autoclaim
        bytes32[] memory requestIds = new bytes32[](3);

        for (uint256 i = 0; i < 3; i++) {
            vm.prank(user);
            vault.approve(address(paymaster), unstakeAmount);

            IKamPaymaster.UnstakeWithAutoclaimRequest memory request = IKamPaymaster.UnstakeWithAutoclaimRequest({
                user: user,
                nonce: uint96(i),
                vault: address(vault),
                deadline: uint96(deadline),
                recipient: user,
                maxFee: DEFAULT_MAX_FEE,
                stkTokenAmount: unstakeAmount
            });

            bytes memory requestSig = _createUnstakeWithAutoclaimRequestSignature(request, userPrivateKey);

            vm.prank(executor);
            requestIds[i] = paymaster.executeRequestUnstakeWithAutoclaim(request, requestSig, fee);
            assertTrue(paymaster.canAutoclaim(requestIds[i]));
        }

        // Execute batch autoclaim
        uint256 userKTokenBalanceBefore = kToken.balanceOf(user);

        vm.prank(executor);
        paymaster.executeAutoclaimUnstakedAssetsBatch(requestIds);

        // Verify all autoclaims were executed
        for (uint256 i = 0; i < 3; i++) {
            assertFalse(paymaster.canAutoclaim(requestIds[i]));
        }
        // User received kTokens from all claims
        assertGt(kToken.balanceOf(user), userKTokenBalanceBefore);
    }

    function test_batchAutoclaim_skipsInvalidRequests() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        // Create one valid stake request with autoclaim
        vm.prank(user);
        kToken.approve(address(paymaster), stakeAmount);

        IKamPaymaster.StakeWithAutoclaimRequest memory request = IKamPaymaster.StakeWithAutoclaimRequest({
            user: user,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            recipient: user,
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount
        });

        bytes memory requestSig = _createStakeWithAutoclaimRequestSignature(request, userPrivateKey);

        vm.prank(executor);
        bytes32 validRequestId = paymaster.executeRequestStakeWithAutoclaim(request, requestSig, fee);

        // Create array with valid and invalid request IDs
        bytes32[] memory requestIds = new bytes32[](3);
        requestIds[0] = keccak256("fake1"); // Invalid - not registered
        requestIds[1] = validRequestId; // Valid
        requestIds[2] = keccak256("fake2"); // Invalid - not registered

        // Execute batch - should not revert
        vm.prank(executor);
        paymaster.executeAutoclaimStakedSharesBatch(requestIds);

        // Only the valid request should have been executed
        assertFalse(paymaster.canAutoclaim(validRequestId));
    }

    function test_executeClaimStakedSharesBatch() public {
        // First create multiple stake requests and execute them
        uint96 stakeAmount = 1000 * 1e6;
        uint96 stakeFee = 10 * 1e6;
        uint96 claimFee = 5 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        bytes32[] memory requestIds = new bytes32[](2);
        IKamPaymaster.ClaimRequest[] memory claimRequests = new IKamPaymaster.ClaimRequest[](2);
        bytes[] memory claimSigs = new bytes[](2);
        uint96[] memory claimFees = new uint96[](2);

        // Create stake requests first
        for (uint256 i = 0; i < 2; i++) {
            vm.prank(user);
            kToken.approve(address(paymaster), stakeAmount);

            IKamPaymaster.StakeRequest memory stakeReq = IKamPaymaster.StakeRequest({
                user: user,
                nonce: uint96(i),
                vault: address(vault),
                deadline: uint96(deadline),
                recipient: user,
                maxFee: DEFAULT_MAX_FEE,
                kTokenAmount: stakeAmount
            });

            bytes memory stakeSig = _createStakeRequestSignature(stakeReq, userPrivateKey);

            vm.prank(executor);
            requestIds[i] = paymaster.executeRequestStake(stakeReq, stakeSig, stakeFee);
        }

        // Now batch claim the staked shares
        for (uint256 i = 0; i < 2; i++) {
            claimRequests[i] = IKamPaymaster.ClaimRequest({
                user: user,
                nonce: uint96(i + 2), // nonces continue from stake requests
                vault: address(vault),
                deadline: uint96(deadline),
                maxFee: DEFAULT_MAX_FEE,
                requestId: requestIds[i]
            });

            claimSigs[i] = _createClaimRequestSignature(claimRequests[i], userPrivateKey);
            claimFees[i] = claimFee;
        }

        // Approve paymaster for fees
        vm.prank(user);
        vault.approve(address(paymaster), claimFee * 2);

        vm.prank(executor);
        paymaster.executeClaimStakedSharesBatch(claimRequests, claimSigs, claimFees);

        assertEq(paymaster.nonces(user), 4); // 2 stakes + 2 claims
    }

    function test_executeClaimUnstakedAssetsBatch() public {
        // First create multiple unstake requests
        uint96 unstakeAmount = 1000 * 1e6;
        uint96 unstakeFee = 10 * 1e6;
        uint96 claimFee = 5 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        bytes32[] memory requestIds = new bytes32[](2);
        IKamPaymaster.ClaimRequest[] memory claimRequests = new IKamPaymaster.ClaimRequest[](2);
        bytes[] memory claimSigs = new bytes[](2);
        uint96[] memory claimFees = new uint96[](2);

        // Create unstake requests first
        for (uint256 i = 0; i < 2; i++) {
            vm.prank(user);
            vault.approve(address(paymaster), unstakeAmount);

            IKamPaymaster.UnstakeRequest memory unstakeReq = IKamPaymaster.UnstakeRequest({
                user: user,
                nonce: uint96(i),
                vault: address(vault),
                deadline: uint96(deadline),
                recipient: user,
                maxFee: DEFAULT_MAX_FEE,
                stkTokenAmount: unstakeAmount
            });

            bytes memory unstakeSig = _createUnstakeRequestSignature(unstakeReq, userPrivateKey);

            vm.prank(executor);
            requestIds[i] = paymaster.executeRequestUnstake(unstakeReq, unstakeSig, unstakeFee);
        }

        // Now batch claim the unstaked assets
        for (uint256 i = 0; i < 2; i++) {
            claimRequests[i] = IKamPaymaster.ClaimRequest({
                user: user,
                nonce: uint96(i + 2),
                vault: address(vault),
                deadline: uint96(deadline),
                maxFee: DEFAULT_MAX_FEE,
                requestId: requestIds[i]
            });

            claimSigs[i] = _createClaimRequestSignature(claimRequests[i], userPrivateKey);
            claimFees[i] = claimFee;
        }

        // Approve paymaster for fees
        vm.prank(user);
        kToken.approve(address(paymaster), claimFee * 2);

        uint256 userKTokenBefore = kToken.balanceOf(user);

        vm.prank(executor);
        paymaster.executeClaimUnstakedAssetsBatch(claimRequests, claimSigs, claimFees);

        assertEq(paymaster.nonces(user), 4);
        assertGt(kToken.balanceOf(user), userKTokenBefore);
    }

    function test_executeRequestStakeWithAutoclaimBatch() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 15 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.StakeWithAutoclaimRequest[] memory requests = new IKamPaymaster.StakeWithAutoclaimRequest[](2);
        bytes[] memory sigs = new bytes[](2);
        uint96[] memory fees = new uint96[](2);

        // Approve total amount upfront
        vm.prank(user);
        kToken.approve(address(paymaster), stakeAmount * 2);

        for (uint256 i = 0; i < 2; i++) {
            requests[i] = IKamPaymaster.StakeWithAutoclaimRequest({
                user: user,
                nonce: uint96(i),
                vault: address(vault),
                deadline: uint96(deadline),
                recipient: user,
                maxFee: DEFAULT_MAX_FEE,
                kTokenAmount: stakeAmount
            });

            sigs[i] = _createStakeWithAutoclaimRequestSignature(requests[i], userPrivateKey);
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

        IKamPaymaster.UnstakeWithAutoclaimRequest[] memory requests = new IKamPaymaster.UnstakeWithAutoclaimRequest[](2);
        bytes[] memory sigs = new bytes[](2);
        uint96[] memory fees = new uint96[](2);

        // Approve total amount upfront
        vm.prank(user);
        vault.approve(address(paymaster), unstakeAmount * 2);

        for (uint256 i = 0; i < 2; i++) {
            requests[i] = IKamPaymaster.UnstakeWithAutoclaimRequest({
                user: user,
                nonce: uint96(i),
                vault: address(vault),
                deadline: uint96(deadline),
                recipient: user,
                maxFee: DEFAULT_MAX_FEE,
                stkTokenAmount: unstakeAmount
            });

            sigs[i] = _createUnstakeWithAutoclaimRequestSignature(requests[i], userPrivateKey);
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

    // Helper functions

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
        returns (IKamPaymaster.PermitSignature memory)
    {
        bytes32 permitTypehash =
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

        bytes32 structHash = keccak256(abi.encode(permitTypehash, owner_, spender, value, nonce, deadline));

        bytes32 domainSeparator = MockERC20Permit(token).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return IKamPaymaster.PermitSignature({ value: value, deadline: deadline, v: v, r: r, s: s });
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
                request.vault,
                request.deadline,
                request.maxFee,
                request.requestId
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", paymaster.DOMAIN_SEPARATOR(), structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return abi.encodePacked(r, s, v);
    }

    function _createStakeWithAutoclaimRequestSignature(
        IKamPaymaster.StakeWithAutoclaimRequest memory request,
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
        IKamPaymaster.UnstakeWithAutoclaimRequest memory request,
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
}
