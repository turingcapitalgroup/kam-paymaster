# TypeScript Integration Guide

This guide explains how to integrate with kPaymaster from a TypeScript application using viem. The frontend handles user signing (MetaMask/wallet), and the backend executor submits transactions.

## Dependencies

```bash
npm install viem
# or
yarn add viem
```

## EIP-712 Type Definitions

```typescript
const STAKE_WITH_AUTOCLAIM_REQUEST_TYPES = {
  StakeWithAutoclaimRequest: [
    { name: "user", type: "address" },
    { name: "nonce", type: "uint96" },
    { name: "vault", type: "address" },
    { name: "deadline", type: "uint96" },
    { name: "recipient", type: "address" },
    { name: "maxFee", type: "uint96" },
    { name: "kTokenAmount", type: "uint256" }
  ]
} as const;

const UNSTAKE_WITH_AUTOCLAIM_REQUEST_TYPES = {
  UnstakeWithAutoclaimRequest: [
    { name: "user", type: "address" },
    { name: "nonce", type: "uint96" },
    { name: "vault", type: "address" },
    { name: "deadline", type: "uint96" },
    { name: "recipient", type: "address" },
    { name: "maxFee", type: "uint96" },
    { name: "stkTokenAmount", type: "uint256" }
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
    name: "executeRequestStakeWithAutoclaimWithPermit",
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
        name: "permit",
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
    name: "executeRequestStakeWithAutoclaim",
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
    name: "executeRequestUnstakeWithAutoclaimWithPermit",
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
        name: "permit",
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
    name: "executeRequestUnstakeWithAutoclaim",
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
    name: "executeAutoclaimStakedShares",
    type: "function",
    inputs: [{ name: "requestId", type: "bytes32" }],
    outputs: [],
    stateMutability: "nonpayable"
  },
  {
    name: "executeAutoclaimUnstakedAssets",
    type: "function",
    inputs: [{ name: "requestId", type: "bytes32" }],
    outputs: [],
    stateMutability: "nonpayable"
  },
  {
    name: "executeAutoclaimStakedSharesBatch",
    type: "function",
    inputs: [{ name: "requestIds", type: "bytes32[]" }],
    outputs: [],
    stateMutability: "nonpayable"
  },
  {
    name: "executeAutoclaimUnstakedAssetsBatch",
    type: "function",
    inputs: [{ name: "requestIds", type: "bytes32[]" }],
    outputs: [],
    stateMutability: "nonpayable"
  },
  {
    name: "canAutoclaim",
    type: "function",
    inputs: [{ name: "requestId", type: "bytes32" }],
    outputs: [{ type: "bool" }],
    stateMutability: "view"
  },
  {
    name: "getAutoclaimAuth",
    type: "function",
    inputs: [{ name: "requestId", type: "bytes32" }],
    outputs: [
      {
        type: "tuple",
        components: [
          { name: "vault", type: "address" },
          { name: "isStake", type: "bool" },
          { name: "executed", type: "bool" }
        ]
      }
    ],
    stateMutability: "view"
  },
  {
    name: "isTrustedExecutor",
    type: "function",
    inputs: [{ name: "executor", type: "address" }],
    outputs: [{ type: "bool" }],
    stateMutability: "view"
  },
  {
    name: "treasury",
    type: "function",
    inputs: [],
    outputs: [{ type: "address" }],
    stateMutability: "view"
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

# Single Permit Model

The paymaster uses a **single permit model**. For every operation, only one permit is needed: the user permits the **paymaster** to pull tokens. The paymaster then internally handles fee deduction and vault approval:

1. Paymaster pulls the full token amount from user via `transferFrom`
2. Paymaster sends fee to treasury
3. Paymaster approves the vault for the net amount (amount - fee)
4. Paymaster forwards the request to the vault on behalf of the user

This means the user only needs **one permit signature** (to the paymaster) plus **one request signature** (the EIP-712 meta-transaction) per operation.

If the user already has sufficient allowance for the paymaster (from a previous permit or `approve`), the permit can be skipped entirely, and the non-permit variant of the function is used.

---

# Frontend (User Signing with MetaMask)

## Setup

```typescript
import {
  createPublicClient,
  createWalletClient,
  custom,
  http,
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

## Sign Permit

Users sign a single permit allowing the paymaster to pull tokens. The permit value should be the full token amount for the operation.

```typescript
async function signPermit(
  walletClient: WalletClient,
  publicClient: PublicClient,
  tokenAddress: `0x${string}`,
  spender: `0x${string}`,
  value: bigint,
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
      value,
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

## Sign Stake With Autoclaim Request

```typescript
async function signStakeWithAutoclaimRequest(
  walletClient: WalletClient,
  paymasterAddress: `0x${string}`,
  request: {
    user: `0x${string}`;
    nonce: bigint;
    vault: `0x${string}`;
    deadline: bigint;
    recipient: `0x${string}`;
    maxFee: bigint;
    kTokenAmount: bigint;
  },
  chain: Chain
): Promise<`0x${string}`> {
  const account = walletClient.account!;

  return walletClient.signTypedData({
    account,
    domain: {
      name: "kPaymaster",
      version: "1",
      chainId: chain.id,
      verifyingContract: paymasterAddress
    },
    types: STAKE_WITH_AUTOCLAIM_REQUEST_TYPES,
    primaryType: "StakeWithAutoclaimRequest",
    message: request
  });
}
```

## Sign Unstake With Autoclaim Request

```typescript
async function signUnstakeWithAutoclaimRequest(
  walletClient: WalletClient,
  paymasterAddress: `0x${string}`,
  request: {
    user: `0x${string}`;
    nonce: bigint;
    vault: `0x${string}`;
    deadline: bigint;
    recipient: `0x${string}`;
    maxFee: bigint;
    stkTokenAmount: bigint;
  },
  chain: Chain
): Promise<`0x${string}`> {
  const account = walletClient.account!;

  return walletClient.signTypedData({
    account,
    domain: {
      name: "kPaymaster",
      version: "1",
      chainId: chain.id,
      verifyingContract: paymasterAddress
    },
    types: UNSTAKE_WITH_AUTOCLAIM_REQUEST_TYPES,
    primaryType: "UnstakeWithAutoclaimRequest",
    message: request
  });
}
```

## Complete Frontend Stake With Autoclaim Flow

With autoclaim, the user signs once and the executor can claim on their behalf after batch settlement. The `maxFee` should cover both the request fee and the future claim fee.

```typescript
async function prepareGaslessStakeWithAutoclaim(
  walletClient: WalletClient,
  publicClient: PublicClient,
  config: {
    paymasterAddress: `0x${string}`;
    vaultAddress: `0x${string}`;
    kTokenAddress: `0x${string}`;
    stakeAmount: bigint;
    maxFee: bigint; // Combined fee for request + claim
  },
  chain: Chain
) {
  const user = walletClient.account!.address;
  const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600); // 1 hour

  const paymasterNonce = await publicClient.readContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "nonces",
    args: [user]
  });

  const request = {
    user,
    nonce: paymasterNonce,
    vault: config.vaultAddress,
    deadline,
    recipient: user,
    maxFee: config.maxFee,
    kTokenAmount: config.stakeAmount
  };

  // Check if user already has sufficient allowance for the paymaster
  const currentAllowance = await publicClient.readContract({
    address: config.kTokenAddress,
    abi: ERC20_ABI,
    functionName: "allowance",
    args: [user, config.paymasterAddress]
  });

  let permit: PermitSignature | undefined;
  const needsPermit = currentAllowance < config.stakeAmount;

  if (needsPermit) {
    const permitSig = await signPermit(
      walletClient,
      publicClient,
      config.kTokenAddress,
      config.paymasterAddress,
      config.stakeAmount,
      deadline,
      chain
    );

    permit = {
      value: config.stakeAmount,
      deadline,
      ...permitSig
    };
  }

  // User signs the autoclaim request
  const requestSig = await signStakeWithAutoclaimRequest(
    walletClient,
    config.paymasterAddress,
    request,
    chain
  );

  return {
    request,
    permit,
    requestSig,
    needsPermit
  };
}
```

## Complete Frontend Unstake With Autoclaim Flow

```typescript
async function prepareGaslessUnstakeWithAutoclaim(
  walletClient: WalletClient,
  publicClient: PublicClient,
  config: {
    paymasterAddress: `0x${string}`;
    vaultAddress: `0x${string}`; // vault is also stkToken
    unstakeAmount: bigint;
    maxFee: bigint; // Combined fee for request + claim
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

  const request = {
    user,
    nonce: paymasterNonce,
    vault: config.vaultAddress,
    deadline,
    recipient: user,
    maxFee: config.maxFee,
    stkTokenAmount: config.unstakeAmount
  };

  // Check if user already has sufficient allowance for the paymaster
  const currentAllowance = await publicClient.readContract({
    address: config.vaultAddress, // stkToken is the vault
    abi: ERC20_ABI,
    functionName: "allowance",
    args: [user, config.paymasterAddress]
  });

  let permit: PermitSignature | undefined;
  const needsPermit = currentAllowance < config.unstakeAmount;

  if (needsPermit) {
    const permitSig = await signPermit(
      walletClient,
      publicClient,
      config.vaultAddress, // stkToken is the vault
      config.paymasterAddress,
      config.unstakeAmount,
      deadline,
      chain
    );

    permit = {
      value: config.unstakeAmount,
      deadline,
      ...permitSig
    };
  }

  // User signs the autoclaim request
  const requestSig = await signUnstakeWithAutoclaimRequest(
    walletClient,
    config.paymasterAddress,
    request,
    chain
  );

  return {
    request,
    permit,
    requestSig,
    needsPermit
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
```

## Execute Stake With Autoclaim

Check allowance and use the appropriate function (with or without permit).

```typescript
async function executeStakeWithAutoclaim(
  executorWallet: WalletClient,
  publicClient: PublicClient,
  data: {
    request: StakeWithAutoclaimRequest;
    permit?: PermitSignature;
    requestSig: `0x${string}`;
  },
  config: {
    paymasterAddress: `0x${string}`;
    kTokenAddress: `0x${string}`;
  },
  fee: bigint
): Promise<`0x${string}`> {
  const user = data.request.user;

  // Check current allowance (kToken to paymaster)
  const allowanceForPaymaster = await publicClient.readContract({
    address: config.kTokenAddress,
    abi: ERC20_ABI,
    functionName: "allowance",
    args: [user, config.paymasterAddress]
  });

  const needsPermit = allowanceForPaymaster < data.request.kTokenAmount;

  // If allowance is sufficient, use the non-permit function
  if (!needsPermit) {
    return executorWallet.writeContract({
      address: config.paymasterAddress,
      abi: PAYMASTER_ABI,
      functionName: "executeRequestStakeWithAutoclaim",
      args: [data.request, data.requestSig, fee]
    });
  }

  // Otherwise use the permit function
  if (!data.permit) {
    throw new Error("Permit required but not provided");
  }

  return executorWallet.writeContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "executeRequestStakeWithAutoclaimWithPermit",
    args: [
      data.request,
      data.permit,
      data.requestSig,
      fee
    ]
  });
}
```

## Execute Unstake With Autoclaim

```typescript
async function executeUnstakeWithAutoclaim(
  executorWallet: WalletClient,
  publicClient: PublicClient,
  data: {
    request: UnstakeWithAutoclaimRequest;
    permit?: PermitSignature;
    requestSig: `0x${string}`;
  },
  config: {
    paymasterAddress: `0x${string}`;
    vaultAddress: `0x${string}`; // stkToken
  },
  fee: bigint
): Promise<`0x${string}`> {
  const user = data.request.user;

  // Check current allowance (stkToken to paymaster)
  const allowanceForPaymaster = await publicClient.readContract({
    address: config.vaultAddress,
    abi: ERC20_ABI,
    functionName: "allowance",
    args: [user, config.paymasterAddress]
  });

  const needsPermit = allowanceForPaymaster < data.request.stkTokenAmount;

  if (!needsPermit) {
    return executorWallet.writeContract({
      address: config.paymasterAddress,
      abi: PAYMASTER_ABI,
      functionName: "executeRequestUnstakeWithAutoclaim",
      args: [data.request, data.requestSig, fee]
    });
  }

  if (!data.permit) {
    throw new Error("Permit required but not provided");
  }

  return executorWallet.writeContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "executeRequestUnstakeWithAutoclaimWithPermit",
    args: [
      data.request,
      data.permit,
      data.requestSig,
      fee
    ]
  });
}
```

## Execute Autoclaim

Autoclaim operations do not require user signatures. The executor calls them after batch settlement using the `requestId` returned from the original stake/unstake with autoclaim.

```typescript
async function executeAutoclaimStakedShares(
  executorWallet: WalletClient,
  publicClient: PublicClient,
  config: {
    paymasterAddress: `0x${string}`;
  },
  requestId: `0x${string}`
): Promise<`0x${string}`> {
  // Verify autoclaim is possible
  const canClaim = await publicClient.readContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "canAutoclaim",
    args: [requestId]
  });

  if (!canClaim) {
    throw new Error("Autoclaim not available for this request");
  }

  return executorWallet.writeContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "executeAutoclaimStakedShares",
    args: [requestId]
  });
}

async function executeAutoclaimUnstakedAssets(
  executorWallet: WalletClient,
  publicClient: PublicClient,
  config: {
    paymasterAddress: `0x${string}`;
  },
  requestId: `0x${string}`
): Promise<`0x${string}`> {
  const canClaim = await publicClient.readContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "canAutoclaim",
    args: [requestId]
  });

  if (!canClaim) {
    throw new Error("Autoclaim not available for this request");
  }

  return executorWallet.writeContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "executeAutoclaimUnstakedAssets",
    args: [requestId]
  });
}
```

## Execute Batch Autoclaim

```typescript
async function executeAutoclaimStakedSharesBatch(
  executorWallet: WalletClient,
  config: {
    paymasterAddress: `0x${string}`;
  },
  requestIds: `0x${string}`[]
): Promise<`0x${string}`> {
  return executorWallet.writeContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "executeAutoclaimStakedSharesBatch",
    args: [requestIds]
  });
}

async function executeAutoclaimUnstakedAssetsBatch(
  executorWallet: WalletClient,
  config: {
    paymasterAddress: `0x${string}`;
  },
  requestIds: `0x${string}`[]
): Promise<`0x${string}`> {
  return executorWallet.writeContract({
    address: config.paymasterAddress,
    abi: PAYMASTER_ABI,
    functionName: "executeAutoclaimUnstakedAssetsBatch",
    args: [requestIds]
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
  "0xb78cb0dd": "PermitFailed",
  "0xeeb4f612": "VaultNotRegistered",
  "0xb2aecbeb": "InsufficientAmountForFee",
  "0x5b7cfc40": "StakeRequestFailed",
  "0xf0fed4f7": "UnstakeRequestFailed",
  "0x8e478e73": "ClaimStakedSharesFailed",
  "0xd5454cc2": "ClaimUnstakedAssetsFailed",
  "0xa24a13a6": "ArrayLengthMismatch",
  "0xec0bb840": "AutoclaimNotRegistered",
  "0xcd883690": "AutoclaimAlreadyExecuted"
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
interface StakeWithAutoclaimRequest {
  user: `0x${string}`;
  nonce: bigint;
  vault: `0x${string}`;
  deadline: bigint;
  recipient: `0x${string}`;
  maxFee: bigint;
  kTokenAmount: bigint;
}

interface UnstakeWithAutoclaimRequest {
  user: `0x${string}`;
  nonce: bigint;
  vault: `0x${string}`;
  deadline: bigint;
  recipient: `0x${string}`;
  maxFee: bigint;
  stkTokenAmount: bigint;
}

interface PermitSignature {
  value: bigint;
  deadline: bigint;
  v: number;
  r: `0x${string}`;
  s: `0x${string}`;
}

interface AutoclaimAuth {
  vault: `0x${string}`;
  isStake: boolean;
  executed: boolean;
}
```

---

# Best Practices

1. **Check allowances before signing permits**: Query on-chain allowance before requesting a permit signature. If the user already has sufficient allowance (from a previous permit), skip the permit and use the non-permit function to save the user a signing step.

2. **Backend checks allowances**: The executor checks on-chain allowances before executing. If sufficient, it uses the non-permit function to save gas.

3. **Fee calculation**: Calculate fees based on gas estimation + margin (e.g., 10%) to account for gas price fluctuations.

4. **Set reasonable deadlines**: 1 hour is usually sufficient for transaction submission.

5. **Handle permit nonces**: Permit nonces are per-token, not per-paymaster. Each permit increments the token's nonce.

6. **Check balances**: Verify user has sufficient token balance before requesting signatures.

7. **Retry logic**: Implement retry for failed transactions with new nonces if the paymaster nonce was consumed.

8. **Validate maxFee**: Ensure the user's signed maxFee covers the actual fee the executor will charge.

9. **Autoclaim fee planning**: When using autoclaim, the `maxFee` must cover both the request fee and the future claim fee. Calculate both fees upfront and sum them for the `maxFee` parameter.

10. **Autoclaim monitoring**: After a stake/unstake with autoclaim, monitor the vault for batch settlement and execute `executeAutoclaimStakedShares` or `executeAutoclaimUnstakedAssets` once the batch is settled.

11. **Batch autoclaim fault tolerance**: Batch autoclaim operations (`executeAutoclaimStakedSharesBatch`, `executeAutoclaimUnstakedAssetsBatch`) are fault-tolerant. If a single claim fails (e.g., not yet settled), it emits `AutoclaimFailed` and continues. Failed claims remain retryable.
