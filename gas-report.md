# Gas Report

> Compiler: Solc 0.8.30 | 36 tests passed

## kPaymaster Contract (`src/kPaymaster.sol`)

| Deployment Cost | Deployment Size |
|-----------------|-----------------|
| 3,293,818       | 15,503          |

| Function Name                                | Min     | Avg     | Median  | Max     | # Calls |
|----------------------------------------------|---------|---------|---------|---------|---------|
| DOMAIN_SEPARATOR                             | 374     | 374     | 374     | 374     | 31      |
| STAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH        | 284     | 284     | 284     | 284     | 22      |
| UNSTAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH      | 304     | 304     | 304     | 304     | 8       |
| canAutoclaim                                 | 2,676   | 2,676   | 2,676   | 2,676   | 29      |
| executeAutoclaimStakedShares                 | 26,576  | 56,936  | 62,315  | 106,616 | 5       |
| executeAutoclaimStakedSharesBatch            | 68,873  | 87,894  | 87,894  | 106,915 | 2       |
| executeAutoclaimUnstakedAssets               | 67,552  | 72,744  | 72,744  | 77,937  | 2       |
| executeAutoclaimUnstakedAssetsBatch          | 113,645 | 113,645 | 113,645 | 113,645 | 1       |
| executeRequestStakeWithAutoclaim             | 196,842 | 248,133 | 265,230 | 265,230 | 8       |
| executeRequestStakeWithAutoclaimBatch        | 386,982 | 386,982 | 386,982 | 386,982 | 1       |
| executeRequestStakeWithAutoclaimWithPermit   | 28,330  | 145,237 | 99,225  | 299,233 | 14      |
| executeRequestUnstakeWithAutoclaim           | 181,236 | 215,433 | 215,436 | 249,624 | 4       |
| executeRequestUnstakeWithAutoclaimBatch      | 369,755 | 369,755 | 369,755 | 369,755 | 1       |
| executeRequestUnstakeWithAutoclaimWithPermit | 268,905 | 276,364 | 276,364 | 283,823 | 2       |
| getAutoclaimAuth                             | 2,876   | 2,876   | 2,876   | 2,876   | 1       |
| isTrustedExecutor                            | 2,641   | 2,641   | 2,641   | 2,641   | 4       |
| nonces                                       | 2,617   | 2,617   | 2,617   | 2,617   | 12      |
| owner                                        | 2,383   | 2,383   | 2,383   | 2,383   | 3       |
| rescueTokens                                 | 52,785  | 52,785  | 52,785  | 52,785  | 1       |
| setTreasury                                  | 23,777  | 26,978  | 26,978  | 30,180  | 2       |
| setTrustedExecutor                           | 26,008  | 47,343  | 47,920  | 47,920  | 38      |
| transferOwnership                            | 28,541  | 28,541  | 28,541  | 28,541  | 1       |
| treasury                                     | 2,425   | 2,425   | 2,425   | 2,425   | 3       |
