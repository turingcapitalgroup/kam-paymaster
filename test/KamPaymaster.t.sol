// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Test } from "forge-std/Test.sol";
import { KamPaymaster } from "../src/KamPaymaster.sol";
import { IKamPaymaster } from "../src/interfaces/IKamPaymaster.sol";
import { IChainlinkAggregator } from "../src/interfaces/IChainlinkAggregator.sol";

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

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(deadline >= block.timestamp, "permit expired");

        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "invalid signature");

        allowance[owner][spender] = value;
    }
}

contract MockChainlinkAggregator is IChainlinkAggregator {
    int256 public price;
    uint8 public decimals_;
    uint256 public updatedAt;

    constructor(int256 _price, uint8 _decimals) {
        price = _price;
        decimals_ = _decimals;
        updatedAt = block.timestamp;
    }

    function setPrice(int256 _price) external {
        price = _price;
        updatedAt = block.timestamp;
    }

    function setUpdatedAt(uint256 _updatedAt) external {
        updatedAt = _updatedAt;
    }

    function latestRoundData()
        external
        view
        override
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 _updatedAt, uint80 answeredInRound)
    {
        return (1, price, block.timestamp, updatedAt, 1);
    }

    function decimals() external view override returns (uint8) {
        return decimals_;
    }
}

contract MockKStakingVault is MockERC20Permit {
    address public kToken;
    uint256 public sharePrice = 1e6;

    constructor(address _kToken) MockERC20Permit("Staked kUSDC", "stkUSDC", 6) {
        kToken = _kToken;
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
        MockERC20Permit(kToken).transferFrom(msg.sender, address(this), amount);
        balanceOf[to] += amount;
        totalSupply += amount;
        return keccak256(abi.encode(to, amount, block.timestamp));
    }

    function requestUnstake(address to, uint256 amount) external payable returns (bytes32) {
        balanceOf[msg.sender] -= amount;
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
    mapping(address => address) public assetToKToken;
    mapping(address => address) public kTokenToAsset;

    function setAssetToKToken(address asset, address _kToken) external {
        assetToKToken[asset] = _kToken;
        kTokenToAsset[_kToken] = asset;
    }
}

contract KamPaymasterTest is Test {
    KamPaymaster public paymaster;
    MockERC20Permit public kToken;
    MockERC20Permit public underlyingAsset;
    MockKStakingVault public vault;
    MockRegistry public registry;
    MockChainlinkAggregator public priceFeed;

    address public owner;
    address public treasury;
    address public user;
    uint256 public userPrivateKey;
    address public executor;

    uint256 constant BASE_FEE = 100;
    uint256 constant GAS_MULTIPLIER = 1e18;
    int256 constant USDC_ETH_PRICE = 5e14;

    function setUp() public {
        owner = makeAddr("owner");
        treasury = makeAddr("treasury");
        executor = makeAddr("executor");
        userPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        user = vm.addr(userPrivateKey);

        underlyingAsset = new MockERC20Permit("USD Coin", "USDC", 6);
        kToken = new MockERC20Permit("KAM USDC", "kUSDC", 6);
        vault = new MockKStakingVault(address(kToken));
        registry = new MockRegistry();
        registry.setAssetToKToken(address(underlyingAsset), address(kToken));

        priceFeed = new MockChainlinkAggregator(USDC_ETH_PRICE, 18);

        vm.prank(owner);
        paymaster = new KamPaymaster(owner, treasury, address(registry), BASE_FEE, GAS_MULTIPLIER);

        vm.prank(owner);
        paymaster.setAssetPriceFeed(address(underlyingAsset), address(priceFeed));

        vm.prank(owner);
        paymaster.setAssetPriceFeed(address(kToken), address(priceFeed));

        vm.prank(owner);
        paymaster.setTrustedExecutor(executor, true);

        kToken.mint(user, 1_000_000 * 1e6);
        vault.mint(user, 1_000_000 * 1e6);
    }

    function test_constructor() public view {
        assertEq(paymaster.owner(), owner);
        assertEq(paymaster.treasury(), treasury);
        assertEq(paymaster.registry(), address(registry));
        assertEq(paymaster.baseFee(), BASE_FEE);
        assertEq(paymaster.gasMultiplier(), GAS_MULTIPLIER);
        assertTrue(paymaster.isTrustedExecutor(owner));
    }

    function test_setAssetPriceFeed() public {
        address newAsset = makeAddr("newAsset");
        address newFeed = makeAddr("newFeed");

        vm.prank(owner);
        paymaster.setAssetPriceFeed(newAsset, newFeed);

        assertEq(paymaster.assetPriceFeeds(newAsset), newFeed);
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

    function test_setFeeConfig() public {
        uint256 newBaseFee = 200;
        uint256 newGasMultiplier = 2e18;

        vm.prank(owner);
        paymaster.setFeeConfig(newBaseFee, newGasMultiplier);

        assertEq(paymaster.baseFee(), newBaseFee);
        assertEq(paymaster.gasMultiplier(), newGasMultiplier);
    }

    function test_revert_setFeeConfig_exceedsMax() public {
        vm.prank(owner);
        vm.expectRevert(IKamPaymaster.FeeExceedsMaximum.selector);
        paymaster.setFeeConfig(6000, GAS_MULTIPLIER);
    }

    function test_revert_notTrustedExecutor() public {
        address notExecutor = makeAddr("notExecutor");

        IKamPaymaster.StakeRequest memory request = IKamPaymaster.StakeRequest({
            user: user,
            vault: address(vault),
            kTokenAmount: 1000 * 1e6,
            recipient: user,
            deadline: block.timestamp + 1 hours,
            nonce: 0
        });

        IKamPaymaster.PermitSignature memory permitSig =
            IKamPaymaster.PermitSignature({ value: 1000 * 1e6, deadline: block.timestamp + 1 hours, v: 27, r: bytes32(0), s: bytes32(0) });

        vm.prank(notExecutor);
        vm.expectRevert(IKamPaymaster.NotTrustedExecutor.selector);
        paymaster.executeStakeWithPermit(request, permitSig, "");
    }

    function test_calculateFeeForKToken() public {
        vm.txGasPrice(50 gwei);
        uint256 fee = paymaster.calculateFeeForKToken(200_000, address(kToken));
        assertGt(fee, 0);
    }

    function test_calculateFeeForStkToken() public {
        vm.txGasPrice(50 gwei);
        uint256 fee = paymaster.calculateFeeForStkToken(200_000, address(vault));
        assertGt(fee, 0);
    }

    function test_revert_noPriceFeedConfigured() public {
        address unknownToken = makeAddr("unknownToken");
        vm.expectRevert(IKamPaymaster.NoPriceFeedConfigured.selector);
        paymaster.calculateFeeForKToken(200_000, unknownToken);
    }

    function test_revert_invalidPriceFeed_negativePrice() public {
        priceFeed.setPrice(-1);
        vm.expectRevert(IKamPaymaster.InvalidPriceFeed.selector);
        paymaster.calculateFeeForKToken(200_000, address(kToken));
    }

    function test_revert_invalidPriceFeed_stalePrice() public {
        vm.warp(10000);
        priceFeed.setUpdatedAt(block.timestamp - 2 hours);
        vm.expectRevert(IKamPaymaster.InvalidPriceFeed.selector);
        paymaster.calculateFeeForKToken(200_000, address(kToken));
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
}
