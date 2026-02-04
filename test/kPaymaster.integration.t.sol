// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { IkPaymaster } from "../src/interfaces/IkPaymaster.sol";
import { kPaymaster } from "../src/kPaymaster.sol";
import { Test } from "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function allowance(address, address) external view returns (uint256);
    function mint(address, uint256) external;
}

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

    function burn(address from, uint256 amount) external {
        balanceOf[from] -= amount;
        totalSupply -= amount;
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
    address public trustedForwarder;

    struct StakeRequest {
        address user;
        uint256 amount;
        address recipient;
        bool claimed;
    }

    struct UnstakeRequest {
        address user;
        uint256 stkAmount;
        address recipient;
        bool claimed;
    }

    mapping(bytes32 => StakeRequest) public stakeRequests;
    mapping(bytes32 => UnstakeRequest) public unstakeRequests;

    bytes32 public currentBatchId;
    bool public batchSettled;
    uint256 public sharePrice = 1e6;
    uint256 private _requestCounter;

    constructor(address _kToken) MockERC20Permit("Staked kUSDC", "stkUSDC", 6) {
        kToken = _kToken;
        currentBatchId = keccak256(abi.encode(block.timestamp, address(this), 0));
    }

    // asset() returns kToken in kStakingVault
    function asset() external view returns (address) {
        return kToken;
    }

    function setTrustedForwarder(address _forwarder) external {
        trustedForwarder = _forwarder;
    }

    function isTrustedForwarder(address forwarder) public view returns (bool) {
        return forwarder == trustedForwarder;
    }

    function _msgSender() internal view returns (address sender) {
        if (isTrustedForwarder(msg.sender) && msg.data.length >= 20) {
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender = msg.sender;
        }
    }

    function getBatchId() external view returns (bytes32) {
        return currentBatchId;
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        return assets * 1e6 / sharePrice;
    }

    function convertToAssets(uint256 shares) external view returns (uint256) {
        return shares * sharePrice / 1e6;
    }

    function requestStake(
        address owner,
        address recipient,
        uint256 amount
    )
        external
        payable
        returns (bytes32 requestId)
    {
        address sender = _msgSender();
        // ERC2771: paymaster forwards call with itself as msg.sender, owner param specifies request owner
        MockERC20Permit(kToken).transferFrom(sender, address(this), amount);
        requestId = keccak256(abi.encode(owner, amount, block.timestamp, ++_requestCounter));
        stakeRequests[requestId] = StakeRequest({ user: owner, amount: amount, recipient: recipient, claimed: false });
    }

    function requestUnstake(
        address owner,
        address recipient,
        uint256 stkAmount
    )
        external
        payable
        returns (bytes32 requestId)
    {
        address sender = _msgSender();
        // ERC2771: paymaster forwards call with itself as msg.sender, owner param specifies request owner
        MockERC20Permit(address(this)).transferFrom(sender, address(this), stkAmount);
        requestId = keccak256(abi.encode(owner, stkAmount, block.timestamp, ++_requestCounter));
        unstakeRequests[requestId] =
            UnstakeRequest({ user: owner, stkAmount: stkAmount, recipient: recipient, claimed: false });
    }

    function claimStakedShares(bytes32 requestId) external payable {
        address sender = _msgSender();
        StakeRequest storage request = stakeRequests[requestId];
        require(request.user == sender, "not request owner");
        require(!request.claimed, "already claimed");
        require(batchSettled, "batch not settled");

        request.claimed = true;
        uint256 shares = request.amount * 1e6 / sharePrice;
        balanceOf[request.recipient] += shares;
        totalSupply += shares;
    }

    function claimUnstakedAssets(bytes32 requestId) external payable {
        address sender = _msgSender();
        UnstakeRequest storage request = unstakeRequests[requestId];
        require(request.user == sender, "not request owner");
        require(!request.claimed, "already claimed");
        require(batchSettled, "batch not settled");

        request.claimed = true;
        uint256 assets = request.stkAmount * sharePrice / 1e6;
        MockERC20Permit(kToken).transfer(request.recipient, assets);
    }

    function closeBatch(bytes32, bool createNew) external {
        if (createNew) {
            currentBatchId = keccak256(abi.encode(block.timestamp, address(this), ++_requestCounter));
        }
    }

    function settleBatch() external {
        batchSettled = true;
    }

    function setSharePrice(uint256 _price) external {
        sharePrice = _price;
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

contract kPaymasterIntegrationTest is Test {
    kPaymaster public paymaster;
    MockERC20Permit public underlyingAsset;
    MockERC20Permit public kToken;
    MockKStakingVault public vault;
    MockRegistry public mockRegistry;

    address public owner;
    address public treasury;
    address public executor;

    uint256 public constant USER_PRIVATE_KEY = 0xA11CE;
    address public testUser;

    uint256 constant _1_USDC = 1e6;
    uint96 constant DEFAULT_FEE = 100 * 1e6; // 100 USDC fee
    uint96 constant DEFAULT_MAX_FEE = 1000 * 1e6; // 1000 USDC max fee

    function setUp() public {
        owner = makeAddr("owner");
        treasury = makeAddr("treasury");
        executor = makeAddr("executor");
        testUser = vm.addr(USER_PRIVATE_KEY);

        underlyingAsset = new MockERC20Permit("USD Coin", "USDC", 6);
        kToken = new MockERC20Permit("KAM USDC", "kUSD", 6);
        vault = new MockKStakingVault(address(kToken));

        // Deploy mock registry and register the vault
        mockRegistry = new MockRegistry();
        mockRegistry.setVault(address(vault), true);

        paymaster = new kPaymaster(owner, treasury, address(mockRegistry));

        vm.prank(owner);
        paymaster.setTrustedExecutor(executor, true);

        vault.setTrustedForwarder(address(paymaster));
        kToken.mint(testUser, 100_000 * _1_USDC);
        kToken.mint(address(vault), 1_000_000 * _1_USDC);
    }

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
        MockERC20Permit t = MockERC20Permit(token);

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                owner_,
                spender,
                value,
                nonce,
                deadline
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", t.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        return IkPaymaster.PermitSignature({ value: value, deadline: deadline, v: v, r: r, s: s });
    }

    function _createStakeRequestSignature(
        IkPaymaster.StakeRequest memory request,
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
        IkPaymaster.UnstakeRequest memory request,
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
        IkPaymaster.ClaimRequest memory request,
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

    function test_setUp() public view {
        assertEq(paymaster.owner(), owner);
        assertEq(paymaster.treasury(), treasury);
        assertTrue(paymaster.isTrustedExecutor(executor));
        assertEq(kToken.balanceOf(testUser), 100_000 * _1_USDC);
    }

    function test_fullGaslessStakeFlow() public {
        bytes32 requestId = _executeGaslessStake(uint96(10_000 * _1_USDC), DEFAULT_FEE);

        vault.settleBatch();

        _executeGaslessClaimStakedShares(requestId);
    }

    function _executeGaslessStake(uint96 stakeAmount, uint96 fee) internal returns (bytes32 requestId) {
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.StakeRequest memory stakeRequest = IkPaymaster.StakeRequest({
            user: testUser,
            nonce: uint96(paymaster.nonces(testUser)),
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        // Single permit for paymaster to pull full amount
        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kToken),
            testUser,
            address(paymaster),
            stakeAmount,
            deadline,
            kToken.nonces(testUser),
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(stakeRequest, USER_PRIVATE_KEY);

        uint256 userKTokenBefore = kToken.balanceOf(testUser);
        uint256 treasuryBefore = kToken.balanceOf(treasury);

        vm.prank(executor);
        requestId = paymaster.executeRequestStakeWithPermit(stakeRequest, permit, requestSig, fee);

        uint256 feeCollected = kToken.balanceOf(treasury) - treasuryBefore;

        assertEq(kToken.balanceOf(testUser), userKTokenBefore - stakeAmount);
        assertEq(feeCollected, fee);
    }

    function _executeGaslessClaimStakedShares(bytes32 requestId) internal {
        uint256 claimDeadline = block.timestamp + 1 hours;
        uint96 claimFee = 5 * 1e6;

        IkPaymaster.ClaimRequest memory claimRequest = IkPaymaster.ClaimRequest({
            user: testUser,
            nonce: uint96(paymaster.nonces(testUser)),
            vault: address(vault),
            deadline: uint96(claimDeadline),
            maxFee: DEFAULT_MAX_FEE,
            requestId: requestId
        });

        // User approves paymaster for fee
        vm.prank(testUser);
        vault.approve(address(paymaster), claimFee);

        bytes memory claimSig = _createClaimRequestSignature(claimRequest, USER_PRIVATE_KEY);

        uint256 userStkBefore = vault.balanceOf(testUser);

        vm.prank(executor);
        paymaster.executeClaimStakedShares(claimRequest, claimSig, claimFee);

        assertGt(vault.balanceOf(testUser), userStkBefore);
    }

    function test_fullGaslessUnstakeFlow() public {
        _performDirectStake(testUser, 20_000 * _1_USDC);

        uint256 userStkBalance = vault.balanceOf(testUser);
        require(userStkBalance > 0, "No stkTokens to unstake");

        bytes32 requestId = _executeGaslessUnstake(uint96(userStkBalance / 2), DEFAULT_FEE);

        vault.settleBatch();

        _executeGaslessClaimUnstakedAssets(requestId);
    }

    function _executeGaslessUnstake(uint96 unstakeAmount, uint96 fee) internal returns (bytes32 requestId) {
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.UnstakeRequest memory unstakeRequest = IkPaymaster.UnstakeRequest({
            user: testUser,
            nonce: uint96(paymaster.nonces(testUser)),
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            stkTokenAmount: unstakeAmount,
            recipient: testUser
        });

        // Single permit model: permit full unstake amount to paymaster
        IkPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(vault),
            testUser,
            address(paymaster),
            unstakeAmount,
            deadline,
            vault.nonces(testUser),
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createUnstakeRequestSignature(unstakeRequest, USER_PRIVATE_KEY);

        uint256 userStkBefore = vault.balanceOf(testUser);
        uint256 treasuryBefore = vault.balanceOf(treasury);

        vm.prank(executor);
        requestId = paymaster.executeRequestUnstakeWithPermit(unstakeRequest, permitSig, requestSig, fee);

        uint256 feeCollected = vault.balanceOf(treasury) - treasuryBefore;

        assertEq(vault.balanceOf(testUser), userStkBefore - unstakeAmount);
        assertEq(feeCollected, fee);
    }

    function _executeGaslessClaimUnstakedAssets(bytes32 requestId) internal {
        uint256 claimDeadline = block.timestamp + 1 hours;
        uint96 claimFee = 5 * 1e6;

        IkPaymaster.ClaimRequest memory claimRequest = IkPaymaster.ClaimRequest({
            user: testUser,
            nonce: uint96(paymaster.nonces(testUser)),
            vault: address(vault),
            deadline: uint96(claimDeadline),
            maxFee: DEFAULT_MAX_FEE,
            requestId: requestId
        });

        // User approves paymaster for fee
        vm.prank(testUser);
        kToken.approve(address(paymaster), claimFee);

        bytes memory claimSig = _createClaimRequestSignature(claimRequest, USER_PRIVATE_KEY);

        uint256 userKTokenBefore = kToken.balanceOf(testUser);

        vm.prank(executor);
        paymaster.executeClaimUnstakedAssets(claimRequest, claimSig, claimFee);

        assertGt(kToken.balanceOf(testUser), userKTokenBefore);
    }

    function test_revert_expiredDeadline() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint256 permitDeadline = block.timestamp + 1 hours;

        IkPaymaster.StakeRequest memory request = IkPaymaster.StakeRequest({
            user: testUser,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(block.timestamp - 1), // Expired request
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        // Single permit for full amount to paymaster
        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kToken),
            testUser,
            address(paymaster),
            stakeAmount,
            permitDeadline,
            kToken.nonces(testUser),
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_RequestExpired.selector);
        paymaster.executeRequestStakeWithPermit(request, permit, requestSig, DEFAULT_FEE);
    }

    function test_revert_invalidNonce() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.StakeRequest memory request = IkPaymaster.StakeRequest({
            user: testUser,
            nonce: 999, // Wrong nonce
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        // Single permit for full amount to paymaster
        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kToken),
            testUser,
            address(paymaster),
            stakeAmount,
            deadline,
            kToken.nonces(testUser),
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_InvalidNonce.selector);
        paymaster.executeRequestStakeWithPermit(request, permit, requestSig, DEFAULT_FEE);
    }

    function test_revert_notTrustedExecutor() public {
        IkPaymaster.StakeRequest memory request = IkPaymaster.StakeRequest({
            user: testUser,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(block.timestamp + 1 hours),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: 1000 * 1e6,
            recipient: testUser
        });

        // Single permit for full amount to paymaster
        IkPaymaster.PermitSignature memory permit = IkPaymaster.PermitSignature({
            value: 1000 * 1e6, deadline: block.timestamp + 1 hours, v: 27, r: bytes32(0), s: bytes32(0)
        });

        address randomUser = makeAddr("random");
        vm.prank(randomUser);
        vm.expectRevert(IkPaymaster.kPaymaster_NotTrustedExecutor.selector);
        paymaster.executeRequestStakeWithPermit(request, permit, "", DEFAULT_FEE);
    }

    function test_revert_insufficientAmountForFee() public {
        uint96 tinyAmount = 1;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.StakeRequest memory request = IkPaymaster.StakeRequest({
            user: testUser,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: tinyAmount,
            recipient: testUser
        });

        // Single permit to paymaster for tiny amount
        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kToken),
            testUser,
            address(paymaster),
            tinyAmount,
            deadline,
            kToken.nonces(testUser),
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IkPaymaster.kPaymaster_InsufficientAmountForFee.selector);
        paymaster.executeRequestStakeWithPermit(request, permit, requestSig, DEFAULT_FEE);
    }

    function test_nonceIncrementsAfterEachOperation() public {
        assertEq(paymaster.nonces(testUser), 0);

        _executeGaslessStakeSimple(testUser, uint96(1000 * _1_USDC), uint96(10 * _1_USDC));
        assertEq(paymaster.nonces(testUser), 1);

        _executeGaslessStakeSimple(testUser, uint96(1000 * _1_USDC), uint96(10 * _1_USDC));
        assertEq(paymaster.nonces(testUser), 2);
    }

    function test_zeroFeeStake() public {
        uint96 stakeAmount = 1000 * 1e6;
        uint96 fee = 0;
        uint256 deadline = block.timestamp + 1 hours;

        IkPaymaster.StakeRequest memory stakeRequest = IkPaymaster.StakeRequest({
            user: testUser,
            nonce: uint96(paymaster.nonces(testUser)),
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: 0, // maxFee of 0 allows 0 fee
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        // Single permit to paymaster for full amount
        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kToken),
            testUser,
            address(paymaster),
            stakeAmount,
            deadline,
            kToken.nonces(testUser),
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(stakeRequest, USER_PRIVATE_KEY);

        uint256 treasuryBefore = kToken.balanceOf(treasury);

        vm.prank(executor);
        paymaster.executeRequestStakeWithPermit(stakeRequest, permit, requestSig, fee);

        assertEq(kToken.balanceOf(treasury), treasuryBefore); // No fee collected
    }

    function _performDirectStake(address user, uint256 amount) internal {
        vm.startPrank(user);
        kToken.approve(address(vault), amount);
        bytes32 requestId = vault.requestStake(user, user, amount);
        vm.stopPrank();

        vault.settleBatch();

        vm.prank(user);
        vault.claimStakedShares(requestId);
    }

    function _executeGaslessStakeSimple(address user, uint96 amount, uint96 fee) internal returns (bytes32) {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 tokenNonce = kToken.nonces(user);

        IkPaymaster.StakeRequest memory request = IkPaymaster.StakeRequest({
            user: user,
            nonce: uint96(paymaster.nonces(user)),
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: amount,
            recipient: user
        });

        // Single permit to paymaster for full amount
        IkPaymaster.PermitSignature memory permit = _createPermitSignature(
            address(kToken), user, address(paymaster), amount, deadline, tokenNonce, USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        return paymaster.executeRequestStakeWithPermit(request, permit, requestSig, fee);
    }
}
