# Inheritable Smart Contract Wallet - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. Single Beneficiary Inheritance Logic Flaw](#H-01)
    - ### [H-02. Ineffective Reentrancy Guard](#H-02)
    - ### [H-03. Unauthorized Ownership Transfer When Only One Beneficiary Exists](#H-03)
    - ### [H-04. Improper Beneficiary Array Management Leading to Fund Distribution Issues](#H-04)
- ## Medium Risk Findings
    - ### [M-01. Timer Reset Missing in Critical Functions](#M-01)



# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #35

### Dates: Mar 6th, 2025 - Mar 13th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-03-inheritable-smart-contract-wallet)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 4
- Medium: 1
- Low: 0


# High Risk Findings

## <a id='H-01'></a>H-01. Single Beneficiary Inheritance Logic Flaw            



## Summary : The `inherit()` function has a logical flaw when only one beneficiary exists, allowing anyone to claim ownership, not just the listed beneficiary.

## Vulnerability Details : When there's only one beneficiary, the `inherit()` function allows `msg.sender` to become the owner without verifying they are the beneficiary:

```Solidity
function inherit() external {
    if (block.timestamp < getDeadline()) {
        revert InactivityPeriodNotLongEnough();
    }
    if (beneficiaries.length == 1) {
        owner = msg.sender; // No check if msg.sender is the beneficiary!
        _setDeadline();
    } else if (beneficiaries.length > 1) {
        isInherited = true;
    } else {
        revert InvalidBeneficiaries();
    }
}
```

## Impact : High. Anyone can steal a contract with a single beneficiary once the timelock expires.&#x20;

## Tools Used

## Recommendations: Add a check to ensure only the registered beneficiary can inherit when there's a single beneficiary:&#x20;

```Solidity
function inherit() external {
    if (block.timestamp < getDeadline()) {
        revert InactivityPeriodNotLongEnough();
    }
    if (beneficiaries.length == 1) {
        if (msg.sender != beneficiaries[0]) {
            revert NotBeneficiary(msg.sender);
        }
        owner = msg.sender;
        _setDeadline();
    } else if (beneficiaries.length > 1) {
        // Only allow a beneficiary to trigger inheritance
        bool isBeneficiary = false;
        for (uint256 i = 0; i < beneficiaries.length; i++) {
            if (msg.sender == beneficiaries[i]) {
                isBeneficiary = true;
                break;
            }
        }
        if (!isBeneficiary) {
            revert NotBeneficiary(msg.sender);
        }
        isInherited = true;
    } else {
        revert InvalidBeneficiaries();
    }
}
```

## <a id='H-02'></a>H-02. Ineffective Reentrancy Guard            



## Summary : The nonReentrant modifier using transient storage is incorrectly implemented, failing to protect against reentrancy attacks

## Vulnerability Details : The code checks `tload(1)` but sets the lock at `tstore(0, 1)`, using different slots. This means the check and the lock are on different storage locations, rendering the reentrancy protection ineffective.

```Solidity
modifier nonReentrant() {
    assembly {
        if tload(1) { revert(0, 0) }
        tstore(0, 1)
    }
    _;
    assembly {
        tstore(0, 0)
    }
}
```

## Impact : `High`. Functions using this modifier remain vulnerable to reentrancy attacks, which could allow draining of funds or manipulation of contract state.

## Tools Used

## Proof of concept : 

```Solidity
function testReentrancyVulnerability() public {
    // Setup a malicious contract that can reenter
    MaliciousReceiver attacker = new MaliciousReceiver(address(inheritanceManager));
    
    // Fund the inheritance manager
    vm.deal(address(inheritanceManager), 10 ether);
    
    // Owner sends ETH to the attacker
    vm.prank(owner);
    inheritanceManager.sendETH(1 ether, address(attacker));
    
    // Verify attacker was able to drain funds through reentrancy
    assertEq(address(inheritanceManager).balance, 0);
}

contract MaliciousReceiver {
    InheritanceManager target;
    uint256 count = 0;
    
    constructor(address _target) {
        target = InheritanceManager(_target);
    }
    
    receive() external payable {
        if (count < 10 && address(target).balance > 0) {
            count++;
            // Reenter and drain
            target.sendETH(address(target).balance, address(this));
        }
    }
}
```

## Recommendations : 

```Solidity
modifier nonReentrant() {
    assembly {
        if tload(0) { revert(0, 0) }
        tstore(0, 1)
    }
    _;
    assembly {
        tstore(0, 0)
    }
}
```

## <a id='H-03'></a>H-03. Unauthorized Ownership Transfer When Only One Beneficiary Exists            



## Summary: In the `inherit()` function, when there is only one beneficiary, the contract sets `owner = msg.sender` without verifying that `msg.sender` is the beneficiary, allowing anyone to claim ownership after the 90-day timelock

## Vulnerability Details : When there's only one beneficiary, the `inherit()` function allows `msg.sender` to become the owner without verifying they are the beneficiary

```Solidity
function inherit() external {
    if (block.timestamp < getDeadline()) {
        revert InactivityPeriodNotLongEnough();
    }
    if (beneficiaries.length == 1) {
        owner = msg.sender; // No check if msg.sender is the beneficiary!
        _setDeadline();
    } else if (beneficiaries.length > 1) {
        isInherited = true;
    } else {
        revert InvalidBeneficiaries();
    }
}
```

This violates the invariant that "After the 90 days only the beneficiaries get access to the funds."\
\
Impact : `High`. Anyone can steal a contract with a single beneficiary once the timelock expires.&#x20;
-------------------------------------------------------------------------------------------------------

## Tools Used

## Recommendations : 

```Solidity
function inherit() external {
    if (block.timestamp < getDeadline()) {
        revert InactivityPeriodNotLongEnough();
    }
    if (beneficiaries.length == 1) {
        require(msg.sender == beneficiaries[0], "Not the beneficiary");
        owner = msg.sender;
        _setDeadline();
    } else if (beneficiaries.length > 1) {
        isInherited = true;
    } else {
        revert InvalidBeneficiaries();
    }
}
```

## <a id='H-04'></a>H-04. Improper Beneficiary Array Management Leading to Fund Distribution Issues            



## Summary : The `removeBeneficiary` function deletes array elements without compacting the array, leaving `address(0)` entries that disrupt equal fund distribution in `withdrawInheritedFunds`

## Vulnerability Details: In removeBeneficiary, delete beneficiaries\[indexToRemove] sets the element to address(0) without adjusting the array length. In withdrawInheritedFunds, the loop iterates over all elements, attempting to send funds to address(0):

* For ETH, this may burn funds or revert.
* For ERC20, safeTransfer may revert, halting distribution.\
  Additionally, \_getBeneficiaryIndex returns 0 if the beneficiary isn’t found, deleting the first element incorrectly.

## Impact: High. This breaks the third invariant by potentially losing funds to address(0) or preventing full distribution, leaving assets stuck in the contract

## Tools Used

## Recommendations: Properly compact the array in removeBeneficiary and add existence checks:

```Solidity
function removeBeneficiary(address _beneficiary) external onlyOwner {
    for (uint256 i = 0; i < beneficiaries.length; i++) {
        if (_beneficiary == beneficiaries[i]) {
            beneficiaries[i] = beneficiaries[beneficiaries.length - 1];
            beneficiaries.pop();
            _setDeadline();
            return;
        }
    }
    revert("Beneficiary not found");
}
```

    
# Medium Risk Findings

## <a id='M-01'></a>M-01. Timer Reset Missing in Critical Functions            



## Summary : Several critical owner functions don't reset the deadline timer, breaking the core invariant that "EVERY transaction the owner does with this contract must reset the 90 days timer."

## Vulnerability Details : The contract has a critical invariant that every owner transaction should reset the timer, but multiple functions don't call `_setDeadline()` including:&#x20;

* `contractInteractions()`
* `createEstateNFT()`
* `removeBeneficiary()`

This violates the first core invariant and could lead to premature inheritance.

## Impact : `High`. The owner could be actively using the wallet through these functions, but since the timer isn't reset, beneficiaries might be able to inherit the wallet even when the owner is still active

## Tools Used

## Recommendations : Add `_setDeadline()` calls to all functions that can only be executed by the owner:&#x20;

```Solidity
function contractInteractions(...) external nonReentrant onlyOwner {
    // existing code
    _setDeadline(); // Add this line
}

function createEstateNFT(...) external onlyOwner {
    // existing code
    _setDeadline(); // Add this line
}

function removeBeneficiary(...) external onlyOwner {
    // existing code
    _setDeadline(); // Add this line
}
```





