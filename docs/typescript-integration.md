# TypeScript Integration Guide

This guide explains how to integrate with KamPaymaster from a TypeScript application using viem. The frontend handles user signing (MetaMask/wallet), and the backend executor submits transactions.

## Dependencies

```bash
npm install viem
# or
yarn add viem
```

## EIP-712 Type Definitions

```typescript
const STAKE_REQUEST_TYPES = {
  StakeRequest: [
    { name: "user", type: "address" },
    { name: "nonce", type: "uint96" },
    { name: "vault", type: "address" },
    { name: "deadline", type: "uint96" },
    { name: "recipient", type: "address" },
    { name: "maxFee", type: "uint96" },
    { name: "kTokenAmount", type: "uint256" }
  ]
} as const;

const UNSTAKE_REQUEST_TYPES = {
  UnstakeRequest: [
    { name: "user", type: "address" },
    { name: "nonce", type: "uint96" },
    { name: "vault", type: "address" },
    { name: "deadline", type: "uint96" },
    { name: "recipient", type: "address" },
    { name: "maxFee", type: "uint96" },
    { name: "stkTokenAmount", type: "uint256" }
  ]
} as const;

const CLAIM_REQUEST_TYPES = {
  ClaimRequest: [
    { name: "user", type: "address" },
    { name: "nonce", type: "uint96" },
    { name: "vault", type: "address" },
    { name: "deadline", type: "uint96" },
    { name: "maxFee", type: "uint96" },
    { name: "requestId", type: "bytes32" }
  ]
} as const;

const PERMIT_TYPES = {
  Permit: [
    { name: "owner", type: "address" },
    { name: "spender", type: "address" },
    { name: "value", type: "uint256" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" }
  ]
} as const;
```

## ABIs

```typescript
const PAYMASTER_ABI = [
  {
    name: "nonces",
    type: "function",
    inputs: [{ name: "user", type: "address" }],
    outputs: [{ type: "uint256" }],
    stateMutability: "view"
  },
  {
    name: "executeRequestStakeWithPermit",
    type: "function",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "user", type: "address" },
          { name: "nonce", type: "uint96" },
          { name: "vault", type: "address" },
          { name: "deadline", type: "uint96" },
          { name: "recipient", type: "address" },
          { name: "maxFee", type: "uint96" },
          { name: "kTokenAmount", type: "uint256" }
        ]
      },
      {
        name: "permitForForwarder",
        type: "tuple",
        components: [
          { name: "value", type: "uint256" },
          { name: "deadline", type: "uint256" },
          { name: "v", type: "uint8" },
          { name: "r", type: "bytes32" },
          { name: "s", type: "bytes32" }
        ]
      },
      {
        name: "permitForVault",
        type: "tuple",
        components: [
          { name: "value", type: "uint256" },
          { name: "deadline", type: "uint256" },
          { name: "v", type: "uint8" },
          { name: "r", type: "bytes32" },
          { name: "s", type: "bytes32" }
        ]
      },
      { name: "requestSig", type: "bytes" },
      { name: "fee", type: "uint96" }
    ],
    outputs: [{ type: "bytes32" }],
    stateMutability: "nonpayable"
  },
  {
    name: "executeRequestStake",
    type: "function",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "user", type: "address" },
          { name: "nonce", type: "uint96" },
          { name: "vault", type: "address" },
          { name: "deadline", type: "uint96" },
          { name: "recipient", type: "address" },
          { name: "maxFee", type: "uint96" },
          { name: "kTokenAmount", type: "uint256" }
        ]
      },
      { name: "requestSig", type: "bytes" },
      { name: "fee", type: "uint96" }
    ],
    outputs: [{ type: "bytes32" }],
    stateMutability: "nonpayable"
  },
  {
    name: "executeRequestUnstakeWithPermit",
    type: "function",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "user", type: "address" },
          { name: "nonce", type: "uint96" },
          { name: "vault", type: "address" },
          { name: "deadline", type: "uint96" },
          { name: "recipient", type: "address" },
          { name: "maxFee", type: "uint96" },
          { name: "stkTokenAmount", type: "uint256" }
        ]
      },
      {
        name: "permitSig",
        type: "tuple",
        components: [
          { name: "value", type: "uint256" },
          { name: "deadline", type: "uint256" },
          { name: "v", type: "uint8" },
          { name: "r", type: "bytes32" },
          { name: "s", type: "bytes32" }
        ]
      },
      { name: "requestSig", type: "bytes" },
      { name: "fee", type: "uint96" }
    ],
    outputs: [{ type: "bytes32" }],
    stateMutability: "nonpayable"
  },
  {
    name: "executeRequestUnstake",
    type: "function",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "user", type: "address" },
          { name: "nonce", type: "uint96" },
          { name: "vault", type: "address" },
          { name: "deadline", type: "uint96" },
          { name: "recipient", type: "address" },
          { name: "maxFee", type: "uint96" },
          { name: "stkTokenAmount", type: "uint256" }
        ]
      },
      { name: "requestSig", type: "bytes" },
      { name: "fee", type: "uint96" }
    ],
    outputs: [{ type: "bytes32" }],
    stateMutability: "nonpayable"
  },
  {
    name: "executeClaimStakedSharesWithPermit",
    type: "function",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "user", type: "address" },
          { name: "nonce", type: "uint96" },
          { name: "vault", type: "address" },
          { name: "deadline", type: "uint96" },
          { name: "maxFee", type: "uint96" },
          { name: "requestId", type: "bytes32" }
        ]
      },
      {
        name: "permitSig",
        type: "tuple",
        components: [
          { name: "value", type: "uint256" },
          { name: "deadline", type: "uint256" },
          { name: "v", type: "uint8" },
          { name: "r", type: "bytes32" },
          { name: "s", type: "bytes32" }
        ]
      },
      { name: "requestSig", type: "bytes" },
      { name: "fee", type: "uint96" }
    ],
    outputs: [],
    stateMutability: "nonpayable"
  },
  {
    name: "executeClaimStakedShares",
    type: "function",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "user", type: "address" },
          { name: "nonce", type: "uint96" },
          { name: "vault", type: "address" },
          { name: "deadline", type: "uint96" },
          { name: "maxFee", type: "uint96" },
          { name: "requestId", type: "bytes32" }
        ]
      },
      { name: "requestSig", type: "bytes" },
      { name: "fee", type: "uint96" }
    ],
    outputs: [],
    stateMutability: "nonpayable"
  },
  {
    name: "executeClaimUnstakedAssetsWithPermit",
    type: "function",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "user", type: "address" },
          { name: "nonce", type: "uint96" },
          { name: "vault", type: "address" },
          { name: "deadline", type: "uint96" },
          { name: "maxFee", type: "uint96" },
          { name: "requestId", type: "bytes32" }
        ]
      },
      {
        name: "permitSig",
        type: "tuple",
        components: [
          { name: "value", type: "uint256" },
          { name: "deadline", type: "uint256" },
          { name: "v", type: "uint8" },
          { name: "r", type: "bytes32" },
          { name: "s", type: "bytes32" }
        ]
      },
      { name: "requestSig", type: "bytes" },
      { name: "fee", type: "uint96" }
    ],
    outputs: [],
    stateMutability: "nonpayable"
  },
  {
    name: "executeClaimUnstakedAssets",
    type: "function",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "user", type: "address" },
          { name: "nonce", type: "uint96" },
          { name: "vault", type: "address" },
          { name: "deadline", type: "uint96" },
          { name: "maxFee", type: "uint96" },
          { name: "requestId", type: "bytes32" }
        ]
      },
      { name: "requestSig", type: "bytes" },
      { name: "fee", type: "uint96" }
    ],
    outputs: [],
    stateMutability: "nonpayable"
  }
] as const;

const ERC20_ABI = [
  {
    name: "nonces",
    type: "function",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [{ type: "uint256" }],
    stateMutability: "view"
  },
  {
    name: "name",
    type: "function",
    inputs: [],
    outputs: [{ type: "string" }],
    stateMutability: "view"
  },
  {
    name: "allowance",
    type: "function",
    inputs: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" }
    ],
    outputs: [{ type: "uint256" }],
    stateMutability: "view"
  }
] as const;
```

---

# Frontend (User Signing with MetaMask)

## Setup

```typescript
import {
  createPublicClient,
  createWalletClient,
  custom,
  http,
  maxUint256,
  type PublicClient,
  type WalletClient,
  type Chain
} from "viem";
import { mainnet } from "viem/chains";

// Connect to user's wallet (MetaMask)
async function connectWallet(): Promise<WalletClient> {
  if (!window.ethereum) {
    throw new Error("MetaMask not installed");
  }

  const [address] = await window.ethereum.request({
    method: "eth_requestAccounts"
  });

  return createWalletClient({
    account: address,
    chain: mainnet,
    transport: custom(window.ethereum)
  });
}

const publicClient = createPublicClient({
  chain: mainnet,
  transport: http()
});
```

## Sign Permit (Max Approval)

Users sign permits with `maxUint256` so they only need to sign once per spender.

```typescript
async function signPermit(
  walletClient: WalletClient,
  publicClient: PublicClient,
  tokenAddress: `0x${string}`,
  spender: `0x${string}`,
  deadline: bigint,
  chain: Chain
): Promise<{ v: number; r: `0x${string}`; s: `0x${string}` }> {
  const account = walletClient.account!;

  const [name, nonce] = await Promise.all([
    publicClient.readContract({
      address: tokenAddress,
      abi: ERC20_ABI,
      functionName: "name"
    }),
    publicClient.readContract({
      address: tokenAddress,
      abi: ERC20_ABI,
      functionName: "nonces",
      args: [account.address]
    })
  ]);

  // User signs in MetaMask
  const signature = await walletClient.signTypedData({
    account,
    domain: {
      name: name as string,
      version: "1",
      chainId: chain.id,
      verifyingContract: tokenAddress
    },
    types: PERMIT_TYPES,
    primaryType: "Permit",
    message: {
      owner: account.address,
      spender,
      value: maxUint256, // Max approval so user only signs once
      nonce,
      deadline
    }
  });

  const r = `0x${signature.slice(2, 66)}` as `0x${string}`;
  const s = `0x${signature.slice(66, 130)}` as `0x${string}`;
  const v = parseInt(signature.slice(130, 132), 16);

  return { v, r, s };
}
```

## Sign Stake Request

```typescript
async function signStakeRequest(
  walletClient: WalletClient,
  paymasterAddress: `0x${string}`,
  request: {
    user: `0x${string}`;
    nonce: bigint;
    deadline: bigint;
    vault: `0x${string}`;
    maxFee: bigint;
    kTokenAmount: bigint;
    recipient: `0x${string}`;
  },
  chain: Chain
): Promise<`0x${string}`> {
  const account = walletClient.account!;

  // User signs in MetaMask
  return walletClient.signTypedData({
    account,
    domain: {
      name: "KamPaymaster",
      version: "1",
      chainId: chain.id,
      verifyingContract: paymasterAddress
    },
    types: STAKE_REQUEST_TYPES,
    primaryType: "StakeRequest",
    message: request
  });
}
```

## Sign Unstake Request

```typescript
async function signUnstakeRequest(
  walletClient: WalletClient,
  paymasterAddress: `0x${string}`,
  request: {
    user: `0x${string}`;
    nonce: bigint;
    deadline: bigint;
    vault: `0x${string}`;
    maxFee: bigint;
    stkTokenAmount: bigint;
    recipient: `0x${string}`;
  },
  chain: Chain
): Promise<`0x${string}`> {
  const account = walletClient.account!;

  return walletClient.signTypedData({
    account,
    domain: {
      name: "KamPaymaster",
      version: "1",
      chainId: chain.id,
      verifyingContract: paymasterAddress
    },
    types: UNSTAKE_REQUEST_TYPES,
    primaryType: "UnstakeRequest",
    message: request
  });
}
```

## Sign Claim Request

```typescript
async function signClaimRequest(
  walletClient: WalletClient,
  paymasterAddress: `0x${string}`,
  request: {
    user: `0x${string}`;
    nonce: bigint;
    deadline: bigint;
    vault: `0x${string}`;
    maxFee: bigint;
    requestId: `0x${string}`;
  },
  chain: Chain
): Promise<`0x${string}`> {
  const account = walletClient.account!;

  return walletClient.signTypedData({
    account,
    domain: {
      name: "KamPaymaster",
      version: "1",
      chainId: chain.id,
      verifyingContract: paymasterAddress
    },
    types: CLAIM_REQUEST_TYPES,
    primaryType: "ClaimRequest",
    message: request
  });
}
```

## Complete Frontend Stake Flow

```typescript
async function prepareGaslessStake(
  walletClient: WalletClient,
  publicClient: PublicClient,
  config: {
    paymasterAddress: `0x${string}`;
    vaultAddress: `0x${string}`;
    kTokenAddress: `0x${string}`;
    stakeAmount: bigint;
    maxFee: bigint;
  },
  chain: Chain
) {
  const user = walletClient.account!.address;
  const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour

  // Get paymaster nonce
  const paymasterNonce = await publicClient.readContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "nonces",
    args: [user]
  });

  const stakeRequest = {
    user,
    nonce: paymasterNonce,
    vault: config.vaultAddress,
    deadline,
    recipient: user,
    maxFee: config.maxFee,
    kTokenAmount: config.stakeAmount
  };

  // User signs permit for paymaster (MetaMask popup #1)
  const permitForPaymaster = await signPermit(
    walletClient,
    publicClient,
    config.kTokenAddress,
    config.paymasterAddress,
    deadline,
    chain
  );

  // User signs permit for vault (MetaMask popup #2)
  const permitForVault = await signPermit(
    walletClient,
    publicClient,
    config.kTokenAddress,
    config.vaultAddress,
    deadline,
    chain
  );

  // User signs stake request (MetaMask popup #3)
  const requestSig = await signStakeRequest(
    walletClient,
    config.paymasterAddress,
    stakeRequest,
    chain
  );

  // Return data to send to backend
  return {
    stakeRequest,
    permitForPaymaster: {
      value: maxUint256,
      deadline,
      ...permitForPaymaster
    },
    permitForVault: {
      value: maxUint256,
      deadline,
      ...permitForVault
    },
    requestSig
  };
}
```

## Complete Frontend Unstake Flow

```typescript
async function prepareGaslessUnstake(
  walletClient: WalletClient,
  publicClient: PublicClient,
  config: {
    paymasterAddress: `0x${string}`;
    vaultAddress: `0x${string}`; // vault is also stkToken
    unstakeAmount: bigint;
    maxFee: bigint;
  },
  chain: Chain
) {
  const user = walletClient.account!.address;
  const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);

  const paymasterNonce = await publicClient.readContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "nonces",
    args: [user]
  });

  const unstakeRequest = {
    user,
    nonce: paymasterNonce,
    vault: config.vaultAddress,
    deadline,
    recipient: user,
    maxFee: config.maxFee,
    stkTokenAmount: config.unstakeAmount
  };

  // User signs permit for paymaster on stkToken (MetaMask popup #1)
  const permitForPaymaster = await signPermit(
    walletClient,
    publicClient,
    config.vaultAddress, // stkToken is the vault
    config.paymasterAddress,
    deadline,
    chain
  );

  // User signs unstake request (MetaMask popup #2)
  const requestSig = await signUnstakeRequest(
    walletClient,
    config.paymasterAddress,
    unstakeRequest,
    chain
  );

  return {
    unstakeRequest,
    permitForPaymaster: {
      value: maxUint256,
      deadline,
      ...permitForPaymaster
    },
    requestSig
  };
}
```

## Complete Frontend Claim Flow

```typescript
async function prepareGaslessClaim(
  walletClient: WalletClient,
  publicClient: PublicClient,
  config: {
    paymasterAddress: `0x${string}`;
    vaultAddress: `0x${string}`;
    feeTokenAddress: `0x${string}`; // stkToken for claimStakedShares, kToken for claimUnstakedAssets
    requestId: `0x${string}`;
    maxFee: bigint;
  },
  chain: Chain
) {
  const user = walletClient.account!.address;
  const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);

  const paymasterNonce = await publicClient.readContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "nonces",
    args: [user]
  });

  const claimRequest = {
    user,
    nonce: paymasterNonce,
    vault: config.vaultAddress,
    deadline,
    maxFee: config.maxFee,
    requestId: config.requestId
  };

  // User signs permit for paymaster (MetaMask popup #1)
  const permitForPaymaster = await signPermit(
    walletClient,
    publicClient,
    config.feeTokenAddress,
    config.paymasterAddress,
    deadline,
    chain
  );

  // User signs claim request (MetaMask popup #2)
  const requestSig = await signClaimRequest(
    walletClient,
    config.paymasterAddress,
    claimRequest,
    chain
  );

  return {
    claimRequest,
    permitForPaymaster: {
      value: maxUint256,
      deadline,
      ...permitForPaymaster
    },
    requestSig
  };
}
```

---

# Backend (Executor)

## Setup

```typescript
import {
  createPublicClient,
  createWalletClient,
  http,
  type PublicClient,
  type WalletClient
} from "viem";
import { mainnet } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

const publicClient = createPublicClient({
  chain: mainnet,
  transport: http(process.env.RPC_URL)
});

const executorWallet = createWalletClient({
  account: privateKeyToAccount(process.env.EXECUTOR_PRIVATE_KEY as `0x${string}`),
  chain: mainnet,
  transport: http(process.env.RPC_URL)
});
```

## Fee Calculation

Calculate fee based on estimated gas cost + margin.

```typescript
async function calculateFee(
  publicClient: PublicClient,
  config: {
    paymasterAddress: `0x${string}`;
    tokenDecimals: number;
    tokenPriceUsd: number; // e.g., 1.0 for USDC
    ethPriceUsd: number;   // e.g., 3000
    marginPercent: number; // e.g., 10 for 10%
  },
  functionName: string,
  args: unknown[]
): Promise<bigint> {
  // Estimate gas for the transaction
  const gasEstimate = await publicClient.estimateContractGas({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName,
    args
  });

  // Get current gas price
  const gasPrice = await publicClient.getGasPrice();

  // Calculate ETH cost
  const ethCost = gasEstimate * gasPrice;

  // Convert ETH cost to token amount
  // ethCost (wei) * ethPriceUsd / tokenPriceUsd / 10^(18-tokenDecimals)
  const tokenAmount = (ethCost * BigInt(Math.floor(config.ethPriceUsd * 1e6))) /
    BigInt(Math.floor(config.tokenPriceUsd * 1e6)) /
    BigInt(10 ** (18 - config.tokenDecimals));

  // Add margin (e.g., 10%)
  const feeWithMargin = (tokenAmount * BigInt(100 + config.marginPercent)) / 100n;

  return feeWithMargin;
}

// Example usage
async function getStakeFee(
  publicClient: PublicClient,
  paymasterAddress: `0x${string}`
): Promise<bigint> {
  // For USDC with 6 decimals
  return calculateFee(
    publicClient,
    {
      paymasterAddress,
      tokenDecimals: 6,
      tokenPriceUsd: 1.0,
      ethPriceUsd: 3000, // Fetch from oracle/API in production
      marginPercent: 10
    },
    "executeRequestStakeWithPermit",
    [
      // Dummy args for gas estimation
      {
        user: "0x0000000000000000000000000000000000000001",
        nonce: 0n,
        deadline: BigInt(Math.floor(Date.now() / 1000) + 3600),
        vault: "0x0000000000000000000000000000000000000002",
        maxFee: 1000000n,
        kTokenAmount: 1000000000n,
        recipient: "0x0000000000000000000000000000000000000001"
      },
      { value: 1000000n, deadline: 0n, v: 27, r: "0x" + "00".repeat(32), s: "0x" + "00".repeat(32) },
      { value: 1000000n, deadline: 0n, v: 27, r: "0x" + "00".repeat(32), s: "0x" + "00".repeat(32) },
      "0x" + "00".repeat(65),
      1000000n
    ]
  );
}
```

## Execute Stake

Check allowances and use the appropriate function.

```typescript
async function executeStake(
  executorWallet: WalletClient,
  publicClient: PublicClient,
  data: {
    stakeRequest: StakeRequest;
    permitForPaymaster: PermitSignature;
    permitForVault: PermitSignature;
    requestSig: `0x${string}`;
  },
  config: {
    paymasterAddress: `0x${string}`;
    vaultAddress: `0x${string}`;
    kTokenAddress: `0x${string}`;
  },
  fee: bigint
): Promise<`0x${string}`> {
  const user = data.stakeRequest.user;

  // Check current allowances
  const [allowanceForPaymaster, allowanceForVault] = await Promise.all([
    publicClient.readContract({
      address: config.kTokenAddress,
      abi: ERC20_ABI,
      functionName: "allowance",
      args: [user, config.paymasterAddress]
    }),
    publicClient.readContract({
      address: config.kTokenAddress,
      abi: ERC20_ABI,
      functionName: "allowance",
      args: [user, config.vaultAddress]
    })
  ]);

  const needsPaymasterPermit = allowanceForPaymaster < fee;
  const needsVaultPermit = allowanceForVault < (data.stakeRequest.kTokenAmount - fee);

  // If both allowances are sufficient, use the non-permit function
  if (!needsPaymasterPermit && !needsVaultPermit) {
    return executorWallet.writeContract({
      address: config.paymasterAddress,
      abi: PAYMASTER_ABI,
      functionName: "executeRequestStake",
      args: [data.stakeRequest, data.requestSig, fee]
    });
  }

  // Otherwise use the permit function
  return executorWallet.writeContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "executeRequestStakeWithPermit",
    args: [
      data.stakeRequest,
      data.permitForPaymaster,
      data.permitForVault,
      data.requestSig,
      fee
    ]
  });
}
```

## Execute Unstake

```typescript
async function executeUnstake(
  executorWallet: WalletClient,
  publicClient: PublicClient,
  data: {
    unstakeRequest: UnstakeRequest;
    permitForPaymaster: PermitSignature;
    requestSig: `0x${string}`;
  },
  config: {
    paymasterAddress: `0x${string}`;
    vaultAddress: `0x${string}`; // stkToken
  },
  fee: bigint
): Promise<`0x${string}`> {
  const user = data.unstakeRequest.user;

  // Check current allowance (stkToken to paymaster)
  const allowanceForPaymaster = await publicClient.readContract({
    address: config.vaultAddress,
    abi: ERC20_ABI,
    functionName: "allowance",
    args: [user, config.paymasterAddress]
  });

  const needsPermit = allowanceForPaymaster < (data.unstakeRequest.stkTokenAmount + fee);

  if (!needsPermit) {
    return executorWallet.writeContract({
      address: config.paymasterAddress,
      abi: PAYMASTER_ABI,
      functionName: "executeRequestUnstake",
      args: [data.unstakeRequest, data.requestSig, fee]
    });
  }

  return executorWallet.writeContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "executeRequestUnstakeWithPermit",
    args: [
      data.unstakeRequest,
      data.permitForPaymaster,
      data.requestSig,
      fee
    ]
  });
}
```

## Execute Claim Staked Shares

```typescript
async function executeClaimStakedShares(
  executorWallet: WalletClient,
  publicClient: PublicClient,
  data: {
    claimRequest: ClaimRequest;
    permitForPaymaster: PermitSignature;
    requestSig: `0x${string}`;
  },
  config: {
    paymasterAddress: `0x${string}`;
    vaultAddress: `0x${string}`; // stkToken - fee is paid in stkToken
  },
  fee: bigint
): Promise<`0x${string}`> {
  const user = data.claimRequest.user;

  // Check current allowance (stkToken to paymaster)
  const allowanceForPaymaster = await publicClient.readContract({
    address: config.vaultAddress,
    abi: ERC20_ABI,
    functionName: "allowance",
    args: [user, config.paymasterAddress]
  });

  const needsPermit = allowanceForPaymaster < fee;

  if (!needsPermit) {
    return executorWallet.writeContract({
      address: config.paymasterAddress,
      abi: PAYMASTER_ABI,
      functionName: "executeClaimStakedShares",
      args: [data.claimRequest, data.requestSig, fee]
    });
  }

  return executorWallet.writeContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "executeClaimStakedSharesWithPermit",
    args: [
      data.claimRequest,
      data.permitForPaymaster,
      data.requestSig,
      fee
    ]
  });
}
```

## Execute Claim Unstaked Assets

```typescript
async function executeClaimUnstakedAssets(
  executorWallet: WalletClient,
  publicClient: PublicClient,
  data: {
    claimRequest: ClaimRequest;
    permitForPaymaster: PermitSignature;
    requestSig: `0x${string}`;
  },
  config: {
    paymasterAddress: `0x${string}`;
    kTokenAddress: `0x${string}`; // fee is paid in kToken
  },
  fee: bigint
): Promise<`0x${string}`> {
  const user = data.claimRequest.user;

  // Check current allowance (kToken to paymaster)
  const allowanceForPaymaster = await publicClient.readContract({
    address: config.kTokenAddress,
    abi: ERC20_ABI,
    functionName: "allowance",
    args: [user, config.paymasterAddress]
  });

  const needsPermit = allowanceForPaymaster < fee;

  if (!needsPermit) {
    return executorWallet.writeContract({
      address: config.paymasterAddress,
      abi: PAYMASTER_ABI,
      functionName: "executeClaimUnstakedAssets",
      args: [data.claimRequest, data.requestSig, fee]
    });
  }

  return executorWallet.writeContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "executeClaimUnstakedAssetsWithPermit",
    args: [
      data.claimRequest,
      data.permitForPaymaster,
      data.requestSig,
      fee
    ]
  });
}
```

---

# Error Handling

```typescript
const ERROR_SIGNATURES: Record<string, string> = {
  "0x3fec4504": "NotTrustedExecutor",
  "0xfef01cd2": "RequestExpired",
  "0x5ff85e3f": "FeeExceedsMax",
  "0x8baa579f": "InvalidSignature",
  "0x756688fe": "InvalidNonce",
  "0x1f2a2005": "ZeroAmount",
  "0xd92e233d": "ZeroAddress",
  "0x1a15a3cc": "PermitExpired",
  "0xb78cb0dd": "PermitFailed"
};

async function executeWithErrorHandling<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error: unknown) {
    if (error && typeof error === "object" && "data" in error) {
      const data = (error as { data: string }).data;
      const selector = data.slice(0, 10);
      const errorName = ERROR_SIGNATURES[selector];
      if (errorName) {
        throw new Error(`Transaction reverted: ${errorName}`);
      }
    }
    throw error;
  }
}
```

---

# TypeScript Types

```typescript
interface StakeRequest {
  user: `0x${string}`;
  nonce: bigint;
  vault: `0x${string}`;
  deadline: bigint;
  recipient: `0x${string}`;
  maxFee: bigint;
  kTokenAmount: bigint;
}

interface UnstakeRequest {
  user: `0x${string}`;
  nonce: bigint;
  vault: `0x${string}`;
  deadline: bigint;
  recipient: `0x${string}`;
  maxFee: bigint;
  stkTokenAmount: bigint;
}

interface ClaimRequest {
  user: `0x${string}`;
  nonce: bigint;
  vault: `0x${string}`;
  deadline: bigint;
  maxFee: bigint;
  requestId: `0x${string}`;
}

interface PermitSignature {
  value: bigint;
  deadline: bigint;
  v: number;
  r: `0x${string}`;
  s: `0x${string}`;
}
```

---

# Best Practices

1. **Use max approval for permits**: Sign permits with `maxUint256` so users only need to sign once per spender. Subsequent transactions can skip the permit if allowance is already set.

2. **Backend checks allowances**: The executor checks on-chain allowances before executing. If sufficient, it uses the non-permit function to save gas.

3. **Fee calculation**: Calculate fees based on gas estimation + margin (e.g., 10%) to account for gas price fluctuations.

4. **Set reasonable deadlines**: 1 hour is usually sufficient for transaction submission.

5. **Handle permit nonces**: Permit nonces are per-token, not per-paymaster. Each permit increments the token's nonce.

6. **Check balances**: Verify user has sufficient token balance before requesting signatures.

7. **Retry logic**: Implement retry for failed transactions with new nonces if the paymaster nonce was consumed.

8. **Validate maxFee**: Ensure the user's signed maxFee covers the actual fee the executor will charge.
