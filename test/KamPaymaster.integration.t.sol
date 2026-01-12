// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { KamPaymaster } from "../src/KamPaymaster.sol";
import { IKamPaymaster } from "../src/interfaces/IKamPaymaster.sol";
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

    function requestStake(address recipient, uint256 amount) external payable returns (bytes32 requestId) {
        address sender = _msgSender();
        // Pull kTokens from the actual user (ERC2771 sender)
        MockERC20Permit(kToken).transferFrom(sender, address(this), amount);
        requestId = keccak256(abi.encode(sender, amount, block.timestamp, ++_requestCounter));
        stakeRequests[requestId] = StakeRequest({ user: sender, amount: amount, recipient: recipient, claimed: false });
    }

    function requestUnstake(address recipient, uint256 stkAmount) external payable returns (bytes32 requestId) {
        address sender = _msgSender();
        require(balanceOf[sender] >= stkAmount, "insufficient balance");
        balanceOf[sender] -= stkAmount;
        balanceOf[address(this)] += stkAmount;
        requestId = keccak256(abi.encode(sender, stkAmount, block.timestamp, ++_requestCounter));
        unstakeRequests[requestId] =
            UnstakeRequest({ user: sender, stkAmount: stkAmount, recipient: recipient, claimed: false });
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

contract KamPaymasterIntegrationTest is Test {
    KamPaymaster public paymaster;
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
    uint128 constant DEFAULT_FEE = 100 * 1e6; // 100 USDC fee
    uint128 constant DEFAULT_MAX_FEE = 1000 * 1e6; // 1000 USDC max fee

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

        paymaster = new KamPaymaster(owner, treasury, address(mockRegistry));

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
        returns (IKamPaymaster.PermitSignature memory)
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
                request.vault,
                request.deadline,
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
        bytes32 requestId = _executeGaslessStake(uint128(10_000 * _1_USDC), DEFAULT_FEE);

        vault.settleBatch();

        _executeGaslessClaimStakedShares(requestId);
    }

    function _executeGaslessStake(uint128 stakeAmount, uint128 fee) internal returns (bytes32 requestId) {
        uint256 deadline = block.timestamp + 1 hours;
        uint128 netAmount = stakeAmount - fee;

        IKamPaymaster.StakeRequest memory stakeRequest = IKamPaymaster.StakeRequest({
            user: testUser,
            nonce: uint96(paymaster.nonces(testUser)),
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        // Permit for forwarder to pull fee
        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kToken), testUser, address(paymaster), fee, deadline, kToken.nonces(testUser), USER_PRIVATE_KEY
        );

        // Permit for vault to pull net staking amount
        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kToken),
            testUser,
            address(vault),
            netAmount,
            deadline,
            kToken.nonces(testUser) + 1,
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(stakeRequest, USER_PRIVATE_KEY);

        uint256 userKTokenBefore = kToken.balanceOf(testUser);
        uint256 treasuryBefore = kToken.balanceOf(treasury);

        vm.prank(executor);
        requestId =
            paymaster.executeRequestStakeWithPermit(stakeRequest, permitForForwarder, permitForVault, requestSig, fee);

        uint256 feeCollected = kToken.balanceOf(treasury) - treasuryBefore;

        assertEq(kToken.balanceOf(testUser), userKTokenBefore - stakeAmount);
        assertEq(feeCollected, fee);
    }

    function _executeGaslessClaimStakedShares(bytes32 requestId) internal {
        uint256 claimDeadline = block.timestamp + 1 hours;
        uint128 claimFee = 5 * 1e6;

        IKamPaymaster.ClaimRequest memory claimRequest = IKamPaymaster.ClaimRequest({
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

        bytes32 requestId = _executeGaslessUnstake(uint128(userStkBalance / 2), DEFAULT_FEE);

        vault.settleBatch();

        _executeGaslessClaimUnstakedAssets(requestId);
    }

    function _executeGaslessUnstake(uint128 unstakeAmount, uint128 fee) internal returns (bytes32 requestId) {
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.UnstakeRequest memory unstakeRequest = IKamPaymaster.UnstakeRequest({
            user: testUser,
            nonce: uint96(paymaster.nonces(testUser)),
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            stkTokenAmount: unstakeAmount,
            recipient: testUser
        });

        // Only need permit to paymaster - vault can pull its own stkTokens from user via ERC2771
        IKamPaymaster.PermitSignature memory permitSig = _createPermitSignature(
            address(vault), testUser, address(paymaster), fee, deadline, vault.nonces(testUser), USER_PRIVATE_KEY
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
        uint128 claimFee = 5 * 1e6;

        IKamPaymaster.ClaimRequest memory claimRequest = IKamPaymaster.ClaimRequest({
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
        uint128 stakeAmount = 1000 * 1e6;
        uint128 netAmount = stakeAmount - DEFAULT_FEE;
        uint256 permitDeadline = block.timestamp + 1 hours;

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: testUser,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(block.timestamp - 1), // Expired request
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        // Use valid permits (not expired), but expired request
        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kToken),
            testUser,
            address(paymaster),
            DEFAULT_FEE,
            permitDeadline,
            kToken.nonces(testUser),
            USER_PRIVATE_KEY
        );

        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kToken),
            testUser,
            address(vault),
            netAmount,
            permitDeadline,
            kToken.nonces(testUser) + 1,
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.RequestExpired.selector);
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, requestSig, DEFAULT_FEE);
    }

    function test_revert_invalidNonce() public {
        uint128 stakeAmount = 1000 * 1e6;
        uint128 netAmount = stakeAmount - DEFAULT_FEE;
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: testUser,
            nonce: 999, // Wrong nonce
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kToken),
            testUser,
            address(paymaster),
            DEFAULT_FEE,
            deadline,
            kToken.nonces(testUser),
            USER_PRIVATE_KEY
        );

        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kToken),
            testUser,
            address(vault),
            netAmount,
            deadline,
            kToken.nonces(testUser) + 1,
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.InvalidNonce.selector);
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, requestSig, DEFAULT_FEE);
    }

    function test_revert_notTrustedExecutor() public {
        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: testUser,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(block.timestamp + 1 hours),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: 1000 * 1e6,
            recipient: testUser
        });

        IKamPaymaster.PermitSignature memory permitForForwarder = IKamPaymaster.PermitSignature({
            value: DEFAULT_FEE, deadline: block.timestamp + 1 hours, v: 27, r: bytes32(0), s: bytes32(0)
        });

        IKamPaymaster.PermitSignature memory permitForVault = IKamPaymaster.PermitSignature({
            value: 900 * 1e6, deadline: block.timestamp + 1 hours, v: 27, r: bytes32(0), s: bytes32(0)
        });

        address randomUser = makeAddr("random");
        vm.prank(randomUser);
        vm.expectRevert(IKamPaymaster.NotTrustedExecutor.selector);
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, "", DEFAULT_FEE);
    }

    function test_revert_insufficientAmountForFee() public {
        uint128 tinyAmount = 1;
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: testUser,
            nonce: 0,
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: tinyAmount,
            recipient: testUser
        });

        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kToken),
            testUser,
            address(paymaster),
            DEFAULT_FEE,
            deadline,
            kToken.nonces(testUser),
            USER_PRIVATE_KEY
        );

        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kToken),
            testUser,
            address(vault),
            tinyAmount,
            deadline,
            kToken.nonces(testUser) + 1,
            USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        vm.expectRevert(IKamPaymaster.InsufficientAmountForFee.selector);
        paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, requestSig, DEFAULT_FEE);
    }

    function test_nonceIncrementsAfterEachOperation() public {
        assertEq(paymaster.nonces(testUser), 0);

        _executeGaslessStakeSimple(testUser, uint128(1000 * _1_USDC), uint128(10 * _1_USDC));
        assertEq(paymaster.nonces(testUser), 1);

        _executeGaslessStakeSimple(testUser, uint128(1000 * _1_USDC), uint128(10 * _1_USDC));
        assertEq(paymaster.nonces(testUser), 2);
    }

    function test_zeroFeeStake() public {
        uint128 stakeAmount = 1000 * 1e6;
        uint128 fee = 0;
        uint256 deadline = block.timestamp + 1 hours;

        IKamPaymaster.StakeRequest memory stakeRequest = IKamPaymaster.StakeRequest({
            user: testUser,
            nonce: uint96(paymaster.nonces(testUser)),
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: 0, // maxFee of 0 allows 0 fee
            kTokenAmount: stakeAmount,
            recipient: testUser
        });

        // Dummy permit for forwarder - won't be executed since fee is 0
        IKamPaymaster.PermitSignature memory permitForForwarder =
            IKamPaymaster.PermitSignature({ value: 0, deadline: deadline, v: 27, r: bytes32(0), s: bytes32(0) });

        // Full amount goes to vault - uses current nonce since forwarder permit is skipped
        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kToken), testUser, address(vault), stakeAmount, deadline, kToken.nonces(testUser), USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(stakeRequest, USER_PRIVATE_KEY);

        uint256 treasuryBefore = kToken.balanceOf(treasury);

        vm.prank(executor);
        paymaster.executeRequestStakeWithPermit(stakeRequest, permitForForwarder, permitForVault, requestSig, fee);

        assertEq(kToken.balanceOf(treasury), treasuryBefore); // No fee collected
    }

    function _performDirectStake(address user, uint256 amount) internal {
        vm.startPrank(user);
        kToken.approve(address(vault), amount);
        bytes32 requestId = vault.requestStake(user, amount);
        vm.stopPrank();

        vault.settleBatch();

        vm.prank(user);
        vault.claimStakedShares(requestId);
    }

    function _executeGaslessStakeSimple(address user, uint128 amount, uint128 fee) internal returns (bytes32) {
        uint256 deadline = block.timestamp + 1 hours;
        uint128 netAmount = amount - fee;
        uint256 tokenNonce = kToken.nonces(user);

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: user,
            nonce: uint96(paymaster.nonces(user)),
            vault: address(vault),
            deadline: uint96(deadline),
            maxFee: DEFAULT_MAX_FEE,
            kTokenAmount: amount,
            recipient: user
        });

        IKamPaymaster.PermitSignature memory permitForForwarder = _createPermitSignature(
            address(kToken), user, address(paymaster), fee, deadline, tokenNonce, USER_PRIVATE_KEY
        );

        IKamPaymaster.PermitSignature memory permitForVault = _createPermitSignature(
            address(kToken), user, address(vault), netAmount, deadline, tokenNonce + 1, USER_PRIVATE_KEY
        );

        bytes memory requestSig = _createStakeRequestSignature(request, USER_PRIVATE_KEY);

        vm.prank(executor);
        return paymaster.executeRequestStakeWithPermit(request, permitForForwarder, permitForVault, requestSig, fee);
    }
}
