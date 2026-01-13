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

    function requestStake(address to, uint256 amount) external payable returns (bytes32) {
        // Use _msgSender() to support ERC2771 forwarding
        MockERC20Permit(kToken).transferFrom(_msgSender(), address(this), amount);
        balanceOf[to] += amount;
        totalSupply += amount;
        return keccak256(abi.encode(to, amount, block.timestamp));
    }

    function requestUnstake(address to, uint256 amount) external payable returns (bytes32) {
        balanceOf[_msgSender()] -= amount;
        return keccak256(abi.encode(to, amount, block.timestamp));
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

        IKamPaymaster.PermitSignature memory permitForForwarder = IKamPaymaster.PermitSignature({
            value: 100 * 1e6, deadline: block.timestamp + 1 hours, v: 27, r: bytes32(0), s: bytes32(0)
        });

        IKamPaymaster.PermitSignature memory permitForVault = IKamPaymaster.PermitSignature({
            value: 900 * 1e6, deadline: block.timestamp + 1 hours, v: 27, r: bytes32(0), s: bytes32(0)
        });

        vm.prank(notExecutor);
        vm.expectRevert(IKamPaymaster.NotTrustedExecutor.selector);
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, "", 100 * 1e6);
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
        uint96 netAmount = stakeAmount - fee;
        uint256 deadline = block.timestamp + 1 hours;

        // Create permit signature for forwarder (to pull fee)
        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kToken), user, address(paymaster), fee, deadline, kToken.nonces(user), userPrivateKey
        );

        // Create permit signature for vault (to pull net staking amount)
        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kToken), user, address(vault), netAmount, deadline, kToken.nonces(user) + 1, userPrivateKey
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
        bytes32 requestId =
            paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, requestSig, fee);

        assertNotEq(requestId, bytes32(0));
        assertEq(kToken.balanceOf(treasury), treasuryBalanceBefore + fee);
        assertEq(paymaster.nonces(user), 1);
    }

    function test_executeStake_withoutPermit() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 10 * 1e6;
        uint96 netAmount = stakeAmount - fee;
        uint256 deadline = block.timestamp + 1 hours;

        // User approves paymaster for fee and vault for net amount
        vm.startPrank(user);
        kToken.approve(address(paymaster), fee);
        kToken.approve(address(vault), netAmount);
        vm.stopPrank();

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

        // Create permit signature for stkToken (vault)
        IKamPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(vault), user, address(paymaster), fee, deadline, vault.nonces(user), userPrivateKey
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

        // User approves paymaster directly
        vm.prank(user);
        vault.approve(address(paymaster), fee);

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
        uint96 netAmount = stakeAmount - fee;
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kToken), user, address(paymaster), fee, deadline, kToken.nonces(user), userPrivateKey
        );

        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kToken), user, address(vault), netAmount, deadline, kToken.nonces(user) + 1, userPrivateKey
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
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, requestSig, fee);
    }

    function test_revert_insufficientAmountForFee() public {
        uint96 stakeAmount = 100 * 1e6;
        uint96 fee = 200 * 1e6; // Fee greater than amount
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kToken), user, address(paymaster), fee, deadline, kToken.nonces(user), userPrivateKey
        );

        // Note: netAmount would be negative but we create permit anyway for test setup
        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kToken), user, address(vault), stakeAmount, deadline, kToken.nonces(user) + 1, userPrivateKey
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
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, requestSig, fee);
    }

    function test_revert_requestExpired() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 10 * 1e6;
        uint96 netAmount = stakeAmount - fee;
        uint256 deadline = block.timestamp - 1; // Already expired
        uint256 permitDeadline = block.timestamp + 1 hours;

        // Use valid permits (not expired), but expired request
        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kToken), user, address(paymaster), fee, permitDeadline, kToken.nonces(user), userPrivateKey
        );

        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kToken), user, address(vault), netAmount, permitDeadline, kToken.nonces(user) + 1, userPrivateKey
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
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, requestSig, fee);
    }

    function test_revert_invalidNonce() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 10 * 1e6;
        uint96 netAmount = stakeAmount - fee;
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kToken), user, address(paymaster), fee, deadline, kToken.nonces(user), userPrivateKey
        );

        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kToken), user, address(vault), netAmount, deadline, kToken.nonces(user) + 1, userPrivateKey
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
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, requestSig, fee);
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
}
