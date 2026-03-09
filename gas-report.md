# Gas Report

> Compiler: Solc 0.8.30 | 36 tests passed

## kPaymaster Contract (`src/kPaymaster.sol`)

| Deployment Cost | Deployment Size |
|-----------------|-----------------|
| 2,542,261       | 11,939          |

| Function Name                                | Min     | Avg     | Median  | Max     | # Calls |
|----------------------------------------------|---------|---------|---------|---------|---------|
| DOMAIN_SEPARATOR                             | 332     | 332     | 332     | 332     | 31      |
| STAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH        | 549     | 549     | 549     | 549     | 22      |
| UNSTAKE_WITH_AUTOCLAIM_REQUEST_TYPEHASH      | 835     | 835     | 835     | 835     | 8       |
| canAutoclaim                                 | 2,403   | 2,403   | 2,403   | 2,403   | 29      |
| executeAutoclaimStakedShares                 | 26,425  | 60,359  | 61,406  | 126,076 | 5       |
| executeAutoclaimStakedSharesBatch            | 68,543  | 86,825  | 86,825  | 105,107 | 2       |
| executeAutoclaimUnstakedAssets               | 66,643  | 100,075 | 100,075 | 133,507 | 2       |
| executeAutoclaimUnstakedAssetsBatch          | 111,441 | 111,441 | 111,441 | 111,441 | 1       |
| executeRequestStakeWithAutoclaim             | 194,214 | 245,505 | 262,602 | 262,602 | 8       |
| executeRequestStakeWithAutoclaimBatch        | 381,788 | 381,788 | 381,788 | 381,788 | 1       |
| executeRequestStakeWithAutoclaimWithPermit   | 28,330  | 222,886 | 108,439 | 552,766 | 14      |
| executeRequestUnstakeWithAutoclaim           | 178,735 | 212,932 | 212,935 | 247,123 | 4       |
| executeRequestUnstakeWithAutoclaimBatch      | 364,324 | 364,324 | 364,324 | 364,324 | 1       |
| executeRequestUnstakeWithAutoclaimWithPermit | 280,532 | 354,795 | 354,795 | 429,059 | 2       |
| getAutoclaimAuth                             | 2,784   | 2,784   | 2,784   | 2,784   | 1       |
| isTrustedExecutor                            | 2,660   | 2,660   | 2,660   | 2,660   | 4       |
| nonces                                       | 2,714   | 2,714   | 2,714   | 2,714   | 12      |
| owner                                        | 2,657   | 2,657   | 2,657   | 2,657   | 3       |
| rescueTokens                                 | 52,838  | 52,838  | 52,838  | 52,838  | 1       |
| setTreasury                                  | 24,238  | 27,432  | 27,432  | 30,627  | 2       |
| setTrustedExecutor                           | 26,111  | 47,446  | 48,023  | 48,023  | 38      |
| transferOwnership                            | 29,021  | 29,021  | 29,021  | 29,021  | 1       |
| treasury                                     | 2,499   | 2,499   | 2,499   | 2,499   | 3       |
