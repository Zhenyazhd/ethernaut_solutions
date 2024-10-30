## My solutions for the https://ethernaut.openzeppelin.com


## Fallback

### Task: 

Look carefully at the contract's code below.
You will beat this level if:
 - you claim ownership of the contract
 - you reduce its balance to 0


```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Fallback {
    mapping(address => uint256) public contributions;
    address public owner;

    constructor() {
        owner = msg.sender;
        contributions[msg.sender] = 1000 * (1 ether);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "caller is not the owner");
        _;
    }

    function contribute() public payable {
        require(msg.value < 0.001 ether);
        contributions[msg.sender] += msg.value;
        if (contributions[msg.sender] > contributions[owner]) {
            owner = msg.sender;
        }
    }

    function getContribution() public view returns (uint256) {
        return contributions[msg.sender];
    }

    function withdraw() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {
        require(msg.value > 0 && contributions[msg.sender] > 0);
        owner = msg.sender;
    }
}
```

<details>
  <summary> Solution Explanation </summary>

1. We can call _contribute()_ with a small amount (e.g., 0.0009 ether) to add a contribution for our address (*contributions[msg.sender] > 0*). 

2. Now, sending an amount directly to the contract we will trigger the *receive()* function because we have an existing contribution. And after that we have an ownership.

3. Now that we are the owner, call withdraw() to transfer the contract’s entire balance to our address.

</details>

__________

## Fallout

### Task: 

Claim ownership of the contract below to complete this level.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "openzeppelin-contracts-06/math/SafeMath.sol";

contract Fallout {
    using SafeMath for uint256;

    mapping(address => uint256) allocations;
    address payable public owner;

    /* constructor */
    function Fal1out() public payable {
        owner = msg.sender;
        allocations[owner] = msg.value;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "caller is not the owner");
        _;
    }

    function allocate() public payable {
        allocations[msg.sender] = allocations[msg.sender].add(msg.value);
    }

    function sendAllocation(address payable allocator) public {
        require(allocations[allocator] > 0);
        allocator.transfer(allocations[allocator]);
    }

    function collectAllocations() public onlyOwner {
        msg.sender.transfer(address(this).balance);
    }

    function allocatorBalance(address allocator) public view returns (uint256) {
        return allocations[allocator];
    }
}
```

<details>
  <summary> Solution Explanation </summary>


Constructors in Solidity versions prior to 0.7.0 need to match the contract name exactly, which in this case should be Fallout(). So we can call *Fal1out()* as regular function recieving the ownership. 

</details>

_________________

## Coin Flip

### Task: 

This is a coin flipping game where you need to build up your winning streak by guessing the outcome of a coin flip. To complete this level you'll need to use your psychic abilities to guess the correct outcome 10 times in a row.


```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CoinFlip {
    uint256 public consecutiveWins;
    uint256 lastHash;
    uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

    constructor() {
        consecutiveWins = 0;
    }

    function flip(bool _guess) public returns (bool) {
        uint256 blockValue = uint256(blockhash(block.number - 1));

        if (lastHash == blockValue) {
            revert();
        }

        lastHash = blockValue;
        uint256 coinFlip = blockValue / FACTOR;
        bool side = coinFlip == 1 ? true : false;

        if (side == _guess) {
            consecutiveWins++;
            return true;
        } else {
            consecutiveWins = 0;
            return false;
        }
    }
}
```

<details>
  <summary> Solution Explanation </summary>

1. The result of the flip is determined by:
```
uint256 coinFlip = blockValue / FACTOR;
bool side = coinFlip == 1 ? true : false;
```
where blockValue is the hash of the previous block (block.number - 1).

2. We can recieve block.number outside and predict the correct value of side using the same formula.

</details>


_________________

## Telephone

### Task: 

Claim ownership of the contract below to complete this level.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Telephone {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function changeOwner(address _owner) public {
        if (tx.origin != msg.sender) {
            owner = _owner;
        }
    }
}
```

<details>
  <summary> Solution Explanation </summary>

The Telephone contract uses tx.origin to ensure that only a call originating from a different address (not the original caller) can change the owner. To claim ownership, we can write an intermediary contract that calls changeOwner on Telephone. This way, msg.sender will be our attacking contract, while tx.origin will still be your address, allowing the ownership transfer.

e.g.:

```solidity
    function attack() public {
        targetContract.changeOwner(msg.sender);
    }
```


</details>


_________________

## Token

### Task: 

The goal of this level is for you to hack the basic token contract below.

You are given 20 tokens to start with and you will beat the level if you somehow manage to get your hands on any additional tokens. Preferably a very large amount of tokens.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Token {
    mapping(address => uint256) balances;
    uint256 public totalSupply;

    constructor(uint256 _initialSupply) public {
        balances[msg.sender] = totalSupply = _initialSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] - _value >= 0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }
}
```

<details>
  <summary> Solution Explanation </summary>

1. Compiler version: 0.6.0 => before the version 0.8 arithmetic operations don't have automatic overflow and underflow checks.
2. So using this check *require(balances[msg.sender] - _value >= 0)* in the case balances[msg.sender] < _value we will underflow operation and recieve a very large value.

e.g. 
```solidity
  token.transfer(myaddress, 21);
```

</details>

_________________

## Delegation

### Task: 

The goal of this level is for you to claim ownership of the instance you are given.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Delegate {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function pwn() public {
        owner = msg.sender;
    }
}

contract Delegation {
    address public owner;
    Delegate delegate;

    constructor(address _delegateAddress) {
        delegate = Delegate(_delegateAddress);
        owner = msg.sender;
    }

    fallback() external {
        (bool result,) = address(delegate).delegatecall(msg.data);
        if (result) {
            this;
        }
    }
}
```

<details>
  <summary> Solution Explanation </summary>

*Delegatecall* keeps the context of the calling contract. So we need to send a transaction with msg.data containing the function selector 0xdd365b8b, which corresponds to pwn() in Delegate. After this the fallback function in Delegation will be activated.
Through delegatecall, Delegation will execute pwn() from Delegate in its own context. This will set owner in Delegation to msg.sender, effectively transferring ownership.

</details>

_________________

## Force

### Task: 

The goal of this level is to make the balance of the contract greater than zero.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Force { /*
                   MEOW ?
         /\_/\   /
    ____/ o o \
    /~____  =ø= /
    (______)__m_m)
                   */ }

```

<details>
  <summary> Solution Explanation </summary>

We can deploy a contract that uses self-destruct and sends its remaining funds to the Force contract. When a contract is destroyed, it can send its balance to any address, including a contract that cannot accept native tokens (i.e., does not implement a receive or fallback function). 

</details>

_________________

## Vault

### Task: 

Unlock the vault to pass the level!

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    bool public locked;
    bytes32 private password;

    constructor(bytes32 _password) {
        locked = true;
        password = _password;
    }

    function unlock(bytes32 _password) public {
        if (password == _password) {
            locked = false;
        }
    }
} 
```

<details>
  <summary> Solution Explanation </summary>

We can simply use the web3.eth.getStorageAt method to read the value directly from the Ethereum blockchain.
 
- web3.eth.getStorageAt(add,0) - locked;
- web3.eth.getStorageAt(add,1) - password;

</details>

_________________

## King

### Task: 

The contract below represents a very simple game: whoever sends it an amount of ether that is larger than the current prize becomes the new king. On such an event, the overthrown king gets paid the new prize, making a bit of ether in the process! As ponzi as it gets xD

Such a fun game. Your goal is to break it.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract King {
    address king;
    uint256 public prize;
    address public owner;

    constructor() payable {
        owner = msg.sender;
        king = msg.sender;
        prize = msg.value;
    }

    receive() external payable {
        require(msg.value >= prize || msg.sender == owner);
        payable(king).transfer(msg.value);
        king = msg.sender;
        prize = msg.value;
    }

    function _king() public view returns (address) {
        return king;
    }
}
```

<details>
  <summary> Solution Explanation </summary>

```solidity
payable(king).transfer(msg.value);
```
The transfer function reverts the transaction if the recipient cannot accept the Ether (e.g., if the recipient is a contract with no receive or fallback function).


</details>

_________________

## Re-entrancy

### Task: 

The goal of this level is for you to steal all the funds from the contract.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

import "openzeppelin-contracts-06/math/SafeMath.sol";

contract Reentrance {
    using SafeMath for uint256;

    mapping(address => uint256) public balances;

    function donate(address _to) public payable {
        balances[_to] = balances[_to].add(msg.value);
    }

    function balanceOf(address _who) public view returns (uint256 balance) {
        return balances[_who];
    }

    function withdraw(uint256 _amount) public {
        if (balances[msg.sender] >= _amount) {
            (bool result,) = msg.sender.call{value: _amount}("");
            if (result) {
                _amount;
            }
            balances[msg.sender] -= _amount;
        }
    }

    receive() external payable {}
}
```

<details>
  <summary> Solution Explanation </summary>

This contract uses *msg.sender.call{value: _amount}("")*  to withdraw funds and updates balance AFTER it. If the user’s address is another contract, we can re-enter the withdraw function before the balance is updated, allowing us to drain funds from the Reentrance contract.

```solidity
    receive() external payable {
        if (address(reentrance).balance > 0) {
            reentrance.withdraw(msg.value);
        }
    }
```

</details>
_________________

## Elevator

### Task: 

This elevator won't let you reach the top of your building. Right?

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface Building {
    function isLastFloor(uint256) external returns (bool);
}

contract Elevator {
    bool public top;
    uint256 public floor;

    function goTo(uint256 _floor) public {
        Building building = Building(msg.sender);

        if (!building.isLastFloor(_floor)) {
            floor = _floor;
            top = building.isLastFloor(floor);
        }
    }
}
```

<details>
  <summary> Solution Explanation </summary>

We can create an isLastFloor function that returns *false* for one specific floor value (the one passed during the first call to isLastFloor in the if condition) and *true* for another value (after the assignment floor = _floor).


</details>
_________________

## Privacy

### Task: 

The creator of this contract was careful enough to protect the sensitive areas of its storage.

Unlock this contract to beat the level.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Privacy {
    bool public locked = true;
    uint256 public ID = block.timestamp;
    uint8 private flattening = 10;
    uint8 private denomination = 255;
    uint16 private awkwardness = uint16(block.timestamp);
    bytes32[3] private data;

    constructor(bytes32[3] memory _data) {
        data = _data;
    }

    function unlock(bytes16 _key) public {
        require(_key == bytes16(data[2]));
        locked = false;
    }

    /*
    A bunch of super advanced solidity algorithms...

      ,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`
      .,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,
      *.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^         ,---/V\
      `*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.    ~|__(o.o)
      ^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'  UU  UU
    */
}
```

<details>
  <summary> Solution Explanation </summary>


we can receive data[2] using web3.eth.getStorageAt:)

was usefull: https://medium.com/coinmonks/learn-solidity-lesson-22-type-casting-656d164b9991

</details>

_________________

## Gatekeeper One 

### Task
Make it past the gatekeeper and register as an entrant to pass this level.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GatekeeperOne {
    address public entrant;

    modifier gateOne() {
        require(msg.sender != tx.origin);
        _;
    }

    modifier gateTwo() {
        require(gasleft() % 8191 == 0);
        _;
    }

    modifier gateThree(bytes8 _gateKey) {
        require(uint32(uint64(_gateKey)) == uint16(uint64(_gateKey)), "GatekeeperOne: invalid gateThree part one");
        require(uint32(uint64(_gateKey)) != uint64(_gateKey), "GatekeeperOne: invalid gateThree part two");
        require(uint32(uint64(_gateKey)) == uint16(uint160(tx.origin)), "GatekeeperOne: invalid gateThree part three");
        _;
    }

    function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
        entrant = tx.origin;
        return true;
    }
}
```

<details>
  <summary> Solution Explanation </summary>


1.	address part: uint16(uint160(tx.origin)) to get the last 16 bits of the address.
2.	_gateKey:
	-	Set the lower 16 bits of _gateKey to address part.
	-	Set the next 16 bits to the same addressPart to satisfy the first condition.
	-	Use any value for the last 32 bits that does not match the lower 32 bits.

</details>

_________________

## Gatekeeper Two

This gatekeeper introduces a few new challenges. Register as an entrant to pass this level.

### Task: 

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GatekeeperTwo {
    address public entrant;

    modifier gateOne() {
        require(msg.sender != tx.origin);
        _;
    }

    modifier gateTwo() {
        uint256 x;
        assembly {
            x := extcodesize(caller())
        }
        require(x == 0);
        _;
    }

    modifier gateThree(bytes8 _gateKey) {
        require(uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ uint64(_gateKey) == type(uint64).max);
        _;
    }

    function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
        entrant = tx.origin;
        return true;
    }
}
```

<details>
  <summary> Solution Explanation </summary>

1. *require(msg.sender != tx.origin)*: condition ensures that msg.sender is different from tx.origin, meaning the call must come from a contract, not an externally-owned account.

2. This condition checks that the contract calling enter has no code at the time of the call.

```solidity
uint256 x;
assembly {
    x := extcodesize(caller())
}
require(x == 0);
```

To satisfy the first two conditions it is enough to make a function call in the contract constructor when the contract does not yet have code at the address.

3. XOR operation between the last 8 bytes of the hash of msg.sender (our contract’s address) and _gateKey results in the maximum uint64 value (type(uint64).max, which is 0xFFFFFFFFFFFFFFFF). To find it: uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ type(uint64).max

```solidity
require(uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ uint64(_gateKey) == type(uint64).max);
```


</details>


## Naught Coin

### Task: 

NaughtCoin is an ERC20 token and you're already holding all of them. The catch is that you'll only be able to transfer them after a 10 year lockout period. Can you figure out how to get them out to another address so that you can transfer them freely? Complete this level by getting your token balance to 0.

```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts-08/token/ERC20/ERC20.sol";

contract NaughtCoin is ERC20 {
    // string public constant name = 'NaughtCoin';
    // string public constant symbol = '0x0';
    // uint public constant decimals = 18;
    uint256 public timeLock = block.timestamp + 10 * 365 days;
    uint256 public INITIAL_SUPPLY;
    address public player;

    constructor(address _player) ERC20("NaughtCoin", "0x0") {
        player = _player;
        INITIAL_SUPPLY = 1000000 * (10 ** uint256(decimals()));
        // _totalSupply = INITIAL_SUPPLY;
        // _balances[player] = INITIAL_SUPPLY;
        _mint(player, INITIAL_SUPPLY);
        emit Transfer(address(0), player, INITIAL_SUPPLY);
    }

    function transfer(address _to, uint256 _value) public override lockTokens returns (bool) {
        super.transfer(_to, _value);
    }

    // Prevent the initial owner from transferring tokens until the timelock has passed
    modifier lockTokens() {
        if (msg.sender == player) {
            require(block.timestamp > timeLock);
            _;
        } else {
            _;
        }
    }
}

```
<details>
  <summary> Solution Explanation </summary>


We don't have lockTokens() modifiers on transferFrom function. In the ERC20 standard, transferFrom allows for token transfers on behalf of another account if an allowance has been set. So we can make an approve for another address and use our tokens.

</details>
_________________

## Preservation

### Task: 

This contract utilizes a library to store two different times for two different timezones. The constructor creates two instances of the library for each time to be stored.

The goal of this level is for you to claim ownership of the instance you are given.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Preservation {
    // public library contracts
    address public timeZone1Library;
    address public timeZone2Library;
    address public owner;
    uint256 storedTime;
    // Sets the function signature for delegatecall
    bytes4 constant setTimeSignature = bytes4(keccak256("setTime(uint256)"));

    constructor(address _timeZone1LibraryAddress, address _timeZone2LibraryAddress) {
        timeZone1Library = _timeZone1LibraryAddress;
        timeZone2Library = _timeZone2LibraryAddress;
        owner = msg.sender;
    }

    // set the time for timezone 1
    function setFirstTime(uint256 _timeStamp) public {
        timeZone1Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
    }

    // set the time for timezone 2
    function setSecondTime(uint256 _timeStamp) public {
        timeZone2Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
    }
}

// Simple library contract to set the time
contract LibraryContract {
    // stores a timestamp
    uint256 storedTime;

    function setTime(uint256 _time) public {
        storedTime = _time;
    }
}
```


<details>
  <summary> Solution Explanation </summary>

The Preservation contract uses the delegatecall function in setFirstTime and setSecondTime, which executes the code of an external contract (timeZone1Library or timeZone2Library) while preserving the context of the Preservation contract. This means any storage writes in the library function affect Preservation’s storage, not the library’s own storage.

In Preservation, timeZone1Library, timeZone2Library, and owner occupy storage slots 0, 1, and 2, respectively. If we can get control of timeZone1Library and overwrite slot 2 (which holds owner), we can assign ourselves as the new owner.

1. create a contract with the function setTime(uint256 _time) - which has uint256 storedTime; - occupies slot 2 as address public owner; in Preservation.
2. the first transaction setFirstTime(uint256 _timeStamp) - we pass the address of the contract we created as uint256. As a result, timeZone1Library is our attacking contract.
3. the second transaction setFirstTime(uint256 _timeStamp) - we pass our address as uint256 and it occupies slot 2 - the owner variable

</details>

_________________

## Recovery

### Task: 

A contract creator has built a very simple token factory contract. Anyone can create new tokens with ease. After deploying the first token contract, the creator sent 0.001 ether to obtain more tokens. They have since lost the contract address.

This level will be completed if you can recover (or remove) the 0.001 ether from the lost contract address.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Recovery {
    //generate tokens
    function generateToken(string memory _name, uint256 _initialSupply) public {
        new SimpleToken(_name, msg.sender, _initialSupply);
    }
}

contract SimpleToken {
    string public name;
    mapping(address => uint256) public balances;

    // constructor
    constructor(string memory _name, address _creator, uint256 _initialSupply) {
        name = _name;
        balances[_creator] = _initialSupply;
    }

    // collect ether in return for tokens
    receive() external payable {
        balances[msg.sender] = msg.value * 10;
    }

    // allow transfers of tokens
    function transfer(address _to, uint256 _amount) public {
        require(balances[msg.sender] >= _amount);
        balances[msg.sender] = balances[msg.sender] - _amount;
        balances[_to] = _amount;
    }

    // clean up after ourselves
    function destroy(address payable _to) public {
        selfdestruct(_to);
    }
}
```

<details>
  <summary> Solution Explanation </summary>

1. Contract addresses are deterministic and are calculated by keccak256(address, nonce) where the address is the address of the contract (or ethereum address that created the transaction) and nonce is the number of contracts the spawning contract has created (or the transaction nonce, for regular transactions).
2. For the first contract deployed by the factory, nonce is 1.
3. keccak256(abi.encodePacked(0xd6, 0x94, creator_address, 0x01)) to get the contract address.
4. Once the contract address is calculated, call the destroy function in SimpleToken, passing any payable address as _to to collect the ether.

</details>

_________________

## MagicNumber

### Task: 

To solve this level, you only need to provide the Ethernaut with a Solver, a contract that responds to whatIsTheMeaningOfLife() with the right 32 byte number.

Easy right? Well... there's a catch.

The solver's code needs to be really tiny. Really reaaaaaallly tiny. Like freakin' really really itty-bitty tiny: 10 bytes at most.

Hint: Perhaps its time to leave the comfort of the Solidity compiler momentarily, and build this one by hand O_o. That's right: Raw EVM bytecode.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MagicNum {
    address public solver;

    constructor() {}

    function setSolver(address _solver) public {
        solver = _solver;
    }

    /*
    ____________/\\\_______/\\\\\\\\\_____        
     __________/\\\\\_____/\\\///////\\\___       
      ________/\\\/\\\____\///______\//\\\__      
       ______/\\\/\/\\\______________/\\\/___     
        ____/\\\/__\/\\\___________/\\\//_____    
         __/\\\\\\\\\\\\\\\\_____/\\\//________   
          _\///////////\\\//____/\\\/___________  
           ___________\/\\\_____/\\\\\\\\\\\\\\\_ 
            ___________\///_____\///////////////__
    */
}
```

<details>
  <summary> Solution Explanation </summary>

USEFULL: https://www.ethervm.io/

1. we need to return 0x2a (42).
2. with the hard limit for the code we should use opcodes: 602a60505260206050f3
3. after we need to caslculate initialization opcode and after concatenated it with runtime opcode we can deploy it as solver. 

</details>


_________________
##  Alien Codex

### Task: 

You've uncovered an Alien contract. Claim ownership to complete the level.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.5.0;

import "../helpers/Ownable-05.sol";

contract AlienCodex is Ownable {
    bool public contact;
    bytes32[] public codex;

    modifier contacted() {
        assert(contact);
        _;
    }

    function makeContact() public {
        contact = true;
    }

    function record(bytes32 _content) public contacted {
        codex.push(_content);
    }

    function retract() public contacted {
        codex.length--;
    }

    function revise(uint256 i, bytes32 _content) public contacted {
        codex[i] = _content;
    }
}
```

<details>
  <summary> Solution Explanation </summary>


1. 	contact is stored at slot 0.
2. The codex dynamic array is stored at slot 1, with its actual data stored at a computed location in storage (the position is determined by keccak256 hash of the storage slot).

3. retract() decreases the length of the codex array without bounds checking. This allows the length to be set to an extremely large number (near 2^256 - 1), effectively enabling us to access any storage slot in the contract.
4. After extending codex to cover the entire storage, we can use revise() to write arbitrary data to any storage slot, including the owner slot (slot 0).

```solidity

    function claimOwnership() public {
        //makeContact to pass the contacted modifier
        target.makeContact();
        //underflow codex length to access arbitrary storage slots
        target.retract();
        //calculate index that maps to storage slot 0 (for owner variable)
        uint256 index = uint256(2**256 - uint256(keccak256(abi.encode(1))));
        //overwrite owner by calling revise
        target.revise(index, bytes32(uint256(msg.sender)));
    }

    function calculateElementSlot(uint256 slot, uint256 index) public pure returns (uint256) {
        bytes32 arrayStartSlot = keccak256(abi.encode(slot));
        return uint256(arrayStartSlot) + index;
    }

    function calculateIndexFromSlot(uint256 slot, uint256 slotNumber) public pure returns (uint256) {
        bytes32 arrayStartSlot = keccak256(abi.encode(slot));
        return uint256(slotNumber - uint256(arrayStartSlot));
    }

```

</details>

_________________

## Denial

### Task: 

This is a simple wallet that drips funds over time. You can withdraw the funds slowly by becoming a withdrawing partner.

If you can deny the owner from withdrawing funds when they call withdraw() (whilst the contract still has funds, and the transaction is of 1M gas or less) you will win this level.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Denial {
    address public partner; // withdrawal partner - pay the gas, split the withdraw
    address public constant owner = address(0xA9E);
    uint256 timeLastWithdrawn;
    mapping(address => uint256) withdrawPartnerBalances; // keep track of partners balances

    function setWithdrawPartner(address _partner) public {
        partner = _partner;
    }

    // withdraw 1% to recipient and 1% to owner
    function withdraw() public {
        uint256 amountToSend = address(this).balance / 100;
        // perform a call without checking return
        // The recipient can revert, the owner will still get their share
        partner.call{value: amountToSend}("");
        payable(owner).transfer(amountToSend);
        // keep track of last withdrawal time
        timeLastWithdrawn = block.timestamp;
        withdrawPartnerBalances[partner] += amountToSend;
    }

    // allow deposit of funds
    receive() external payable {}

    // convenience function
    function contractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
```

<details>
  <summary> Solution Explanation </summary>

1.	The withdraw function in the Denial contract transfers amountToSend to both the partner and the owner.
2.	The line partner.call{value: amountToSend}(""); sends ether to the partner without checking for successful execution, and it does not limit gas usage. This makes it vulnerable to a gas-draining attack.
3.	When the partner’s fallback or receive function is executed, it can consume all the remaining gas, which means that there will be no gas left for the transfer call to the owner.

```solidity
    fallback() external payable {
        uint256 i;
        while (true) { ++i }
    }
```

</details>


_________________

## Shop

### Task: 

Сan you get the item from the shop for less than the price asked?

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface Buyer {
    function price() external view returns (uint256);
}

contract Shop {
    uint256 public price = 100;
    bool public isSold;

    function buy() public {
        Buyer _buyer = Buyer(msg.sender);

        if (_buyer.price() >= price && !isSold) {
            isSold = true;
            price = _buyer.price();
        }
    }
}
```

<details>
  <summary> Solution Explanation </summary>


```solidity

   function price() external view override returns (uint256) {
        return target.isSold() ? 0 : 100;
    }
```

</details>
_________________

## Dex

### Task: 

The goal of this level is for you to hack the basic DEX contract below and steal the funds by price manipulation.

You will start with 10 tokens of token1 and 10 of token2. The DEX contract starts with 100 of each token.

You will be successful in this level if you manage to drain all of at least 1 of the 2 tokens from the contract, and allow the contract to report a "bad" price of the assets.


```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts-08/token/ERC20/IERC20.sol";
import "openzeppelin-contracts-08/token/ERC20/ERC20.sol";
import "openzeppelin-contracts-08/access/Ownable.sol";

contract Dex is Ownable {
    address public token1;
    address public token2;

    constructor() {}

    function setTokens(address _token1, address _token2) public onlyOwner {
        token1 = _token1;
        token2 = _token2;
    }

    function addLiquidity(address token_address, uint256 amount) public onlyOwner {
        IERC20(token_address).transferFrom(msg.sender, address(this), amount);
    }

    function swap(address from, address to, uint256 amount) public {
        require((from == token1 && to == token2) || (from == token2 && to == token1), "Invalid tokens");
        require(IERC20(from).balanceOf(msg.sender) >= amount, "Not enough to swap");
        uint256 swapAmount = getSwapPrice(from, to, amount);
        IERC20(from).transferFrom(msg.sender, address(this), amount);
        IERC20(to).approve(address(this), swapAmount);
        IERC20(to).transferFrom(address(this), msg.sender, swapAmount);
    }

    function getSwapPrice(address from, address to, uint256 amount) public view returns (uint256) {
        return ((amount * IERC20(to).balanceOf(address(this))) / IERC20(from).balanceOf(address(this)));
    }

    function approve(address spender, uint256 amount) public {
        SwappableToken(token1).approve(msg.sender, spender, amount);
        SwappableToken(token2).approve(msg.sender, spender, amount);
    }

    function balanceOf(address token, address account) public view returns (uint256) {
        return IERC20(token).balanceOf(account);
    }
}

contract SwappableToken is ERC20 {
    address private _dex;

    constructor(address dexInstance, string memory name, string memory symbol, uint256 initialSupply)
        ERC20(name, symbol)
    {
        _mint(msg.sender, initialSupply);
        _dex = dexInstance;
    }

    function approve(address owner, address spender, uint256 amount) public {
        require(owner != _dex, "InvalidApprover");
        super._approve(owner, spender, amount);
    }
}

```

<details>
  <summary> Solution Explanation </summary>


getSwapPrice(): The function getSwapPrice() calculates the swap price based on the division. Because the reserves of each token are updated with each swap, swapping can shift the token reserves and therefore the price. The division in it won't always calculate to a perfect integer, but a fraction and we will loos some parts of tokens.

We can swap as much as possible of token1 for token2, then vice versa. Each swap will change the price, allowing us to receive increasingly larger amounts of tokens each time.

By repeating the swaps, the contract’s reserves of one token will eventually be exhausted.

</details>
_________________

## Dex Two

### Task: 

This level will ask you to break DexTwo, a subtlely modified Dex contract from the previous level, in a different way.

You need to drain all balances of token1 and token2 from the DexTwo contract to succeed in this level.

You will still start with 10 tokens of token1 and 10 of token2. The DEX contract still starts with 100 of each token.


```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts-08/token/ERC20/IERC20.sol";
import "openzeppelin-contracts-08/token/ERC20/ERC20.sol";
import "openzeppelin-contracts-08/access/Ownable.sol";

contract DexTwo is Ownable {
    address public token1;
    address public token2;

    constructor() {}

    function setTokens(address _token1, address _token2) public onlyOwner {
        token1 = _token1;
        token2 = _token2;
    }

    function add_liquidity(address token_address, uint256 amount) public onlyOwner {
        IERC20(token_address).transferFrom(msg.sender, address(this), amount);
    }

    function swap(address from, address to, uint256 amount) public {
        require(IERC20(from).balanceOf(msg.sender) >= amount, "Not enough to swap");
        uint256 swapAmount = getSwapAmount(from, to, amount);
        IERC20(from).transferFrom(msg.sender, address(this), amount);
        IERC20(to).approve(address(this), swapAmount);
        IERC20(to).transferFrom(address(this), msg.sender, swapAmount);
    }

    function getSwapAmount(address from, address to, uint256 amount) public view returns (uint256) {
        return ((amount * IERC20(to).balanceOf(address(this))) / IERC20(from).balanceOf(address(this)));
    }

    function approve(address spender, uint256 amount) public {
        SwappableTokenTwo(token1).approve(msg.sender, spender, amount);
        SwappableTokenTwo(token2).approve(msg.sender, spender, amount);
    }

    function balanceOf(address token, address account) public view returns (uint256) {
        return IERC20(token).balanceOf(account);
    }
}

contract SwappableTokenTwo is ERC20 {
    address private _dex;

    constructor(address dexInstance, string memory name, string memory symbol, uint256 initialSupply)
        ERC20(name, symbol)
    {
        _mint(msg.sender, initialSupply);
        _dex = dexInstance;
    }

    function approve(address owner, address spender, uint256 amount) public {
        require(owner != _dex, "InvalidApprover");
        super._approve(owner, spender, amount);
    }
}

```

<details>
  <summary> Solution Explanation </summary>

The same idea like in the previous one, but we need to add our propre token to drain two tokens.


</details>

_________________

## Puzzle Wallet

### Task: 

Nowadays, paying for DeFi operations is impossible, fact.

A group of friends discovered how to slightly decrease the cost of performing multiple transactions by batching them in one transaction, so they developed a smart contract for doing this.

They needed this contract to be upgradeable in case the code contained a bug, and they also wanted to prevent people from outside the group from using it. To do so, they voted and assigned two people with special roles in the system: The admin, which has the power of updating the logic of the smart contract. The owner, which controls the whitelist of addresses allowed to use the contract. The contracts were deployed, and the group was whitelisted. Everyone cheered for their accomplishments against evil miners.

Little did they know, their lunch money was at risk…

- You'll need to hijack this wallet to become the admin of the proxy.


```solidity

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

import "../helpers/UpgradeableProxy-08.sol";

contract PuzzleProxy is UpgradeableProxy {
    address public pendingAdmin;
    address public admin;

    constructor(address _admin, address _implementation, bytes memory _initData)
        UpgradeableProxy(_implementation, _initData)
    {
        admin = _admin;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Caller is not the admin");
        _;
    }

    function proposeNewAdmin(address _newAdmin) external {
        pendingAdmin = _newAdmin;
    }

function approveNewAdmin(address _expectedAdmin) external onlyAdmin {
        require(pendingAdmin == _expectedAdmin, "Expected new admin by the current admin is not the pending admin");
        admin = pendingAdmin;
    }

    function upgradeTo(address _newImplementation) external onlyAdmin {
        _upgradeTo(_newImplementation);
    }
}

contract PuzzleWallet {
    address public owner;
    uint256 public maxBalance;
    mapping(address => bool) public whitelisted;
    mapping(address => uint256) public balances;

    function init(uint256 _maxBalance) public {
        require(maxBalance == 0, "Already initialized");
        maxBalance = _maxBalance;
        owner = msg.sender;
    }

    modifier onlyWhitelisted() {
        require(whitelisted[msg.sender], "Not whitelisted");
        _;
    }

    function setMaxBalance(uint256 _maxBalance) external onlyWhitelisted {
        require(address(this).balance == 0, "Contract balance is not 0");
        maxBalance = _maxBalance;
    }

    function addToWhitelist(address addr) external {
        require(msg.sender == owner, "Not the owner");
        whitelisted[addr] = true;
    }

    function deposit() external payable onlyWhitelisted {
        require(address(this).balance <= maxBalance, "Max balance reached");
        balances[msg.sender] += msg.value;
    }

    function execute(address to, uint256 value, bytes calldata data) external payable onlyWhitelisted {
        require(balances[msg.sender] >= value, "Insufficient balance");
        balances[msg.sender] -= value;
        (bool success,) = to.call{value: value}(data);
        require(success, "Execution failed");
    }

    function multicall(bytes[] calldata data) external payable onlyWhitelisted {
        bool depositCalled = false;
        for (uint256 i = 0; i < data.length; i++) {
            bytes memory _data = data[i];
            bytes4 selector;
            assembly {
                selector := mload(add(_data, 32))
            }
            if (selector == this.deposit.selector) {
                require(!depositCalled, "Deposit can only be called once");
                // Protect against reusing msg.value
                depositCalled = true;
            }
            (bool success,) = address(this).delegatecall(data[i]);
            require(success, "Error while delegating call");
        }
    }
}

```

<details>
  <summary> Solution Explanation </summary>

We upgradeable pattern which consists of two contracts - A Proxy contract (Storage layer) and an Implementation contract (Logic layer).
	
Both the PuzzleProxy and PuzzleWallet contracts store data in the same storage layout, leading to a vulnerability where certain state variables overlap. Specifically:

- The admin variable in PuzzleProxy overlaps with the owner variable in PuzzleWallet.

- Since PuzzleProxy allows us to set the owner in PuzzleWallet, by setting ourselves as the owner, we also indirectly gain control over the admin in PuzzleProxy.

- The multicall function allows us to batch multiple operations in one call, including multiple deposit() calls. By carefully crafting these calls, we can drain the funds.

1. Call proposeNewAdmin(address_player) 	
2. Call the addToWhitelist() function in PuzzleWallet to add yourself to the whitelist.
3. Call the multicall with deposit selector.
4. Call execute to drain the contract
5. Call setMaxBalance to set the value of maxBalance on slot 1, and therefore, setting the value for the proxy admin.

```jsx
functionSignature = {
    name: 'proposeNewAdmin',
    type: 'function',
    inputs: [
        {
            type: 'address',
            name: '_newAdmin'
        }
    ]
}

params = ['0xDAc70eD79011695F414E18474868C0cDC808B493']

data = web3.eth.abi.encodeFunctionCall(functionSignature, params)

await web3.eth.sendTransaction({from: '0xDAc70eD79011695F414E18474868C0cDC808B493', to: '0xdf05818BA67C4725164E8961f5C80444556c7Dc8', data})

depositData = await contract.methods["deposit()"].request().then(v => v.data)
multicallData = await contract.methods["multicall(bytes[])"].request([depositData]).then(v => v.data)

'0xac9650d80000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004d0e30db000000000000000000000000000000000000000000000000000000000'
```

</details>

_________________
## DoubleEntryPoint

### Task: 

This level features a CryptoVault with special functionality, the sweepToken function. This is a common function used to retrieve tokens stuck in a contract. The CryptoVault operates with an underlying token that can't be swept, as it is an important core logic component of the CryptoVault. Any other tokens can be swept.

The underlying token is an instance of the DET token implemented in the DoubleEntryPoint contract definition and the CryptoVault holds 100 units of it. Additionally the CryptoVault also holds 100 of LegacyToken LGT.

In this level you should figure out where the bug is in CryptoVault and protect it from being drained out of tokens.

The contract features a Forta contract where any user can register its own detection bot contract. Forta is a decentralized, community-based monitoring network to detect threats and anomalies on DeFi, NFT, governance, bridges and other Web3 systems as quickly as possible. Your job is to implement a detection bot and register it in the Forta contract. The bot's implementation will need to raise correct alerts to prevent potential attacks or bug exploits.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts-08/access/Ownable.sol";
import "openzeppelin-contracts-08/token/ERC20/ERC20.sol";

interface DelegateERC20 {
    function delegateTransfer(address to, uint256 value, address origSender) external returns (bool);
}

interface IDetectionBot {
    function handleTransaction(address user, bytes calldata msgData) external;
}

interface IForta {
    function setDetectionBot(address detectionBotAddress) external;
    function notify(address user, bytes calldata msgData) external;
    function raiseAlert(address user) external;
}

contract Forta is IForta {
    mapping(address => IDetectionBot) public usersDetectionBots;
    mapping(address => uint256) public botRaisedAlerts;

    function setDetectionBot(address detectionBotAddress) external override {
        usersDetectionBots[msg.sender] = IDetectionBot(detectionBotAddress);
    }

    function notify(address user, bytes calldata msgData) external override {
        if (address(usersDetectionBots[user]) == address(0)) return;
        try usersDetectionBots[user].handleTransaction(user, msgData) {
            return;
        } catch {}
    }

    function raiseAlert(address user) external override {
        if (address(usersDetectionBots[user]) != msg.sender) return;
        botRaisedAlerts[msg.sender] += 1;
    }
}

contract CryptoVault {
    address public sweptTokensRecipient;
    IERC20 public underlying;

    constructor(address recipient) {
        sweptTokensRecipient = recipient;
    }

    function setUnderlying(address latestToken) public {
        require(address(underlying) == address(0), "Already set");
        underlying = IERC20(latestToken);
    }

    /*
    ...
    */

    function sweepToken(IERC20 token) public {
        require(token != underlying, "Can't transfer underlying token");
        token.transfer(sweptTokensRecipient, token.balanceOf(address(this)));
    }
}

contract LegacyToken is ERC20("LegacyToken", "LGT"), Ownable {
    DelegateERC20 public delegate;

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    function delegateToNewContract(DelegateERC20 newContract) public onlyOwner {
        delegate = newContract;
    }

    function transfer(address to, uint256 value) public override returns (bool) {
        if (address(delegate) == address(0)) {
            return super.transfer(to, value);
        } else {
            return delegate.delegateTransfer(to, value, msg.sender);
        }
    }
}

contract DoubleEntryPoint is ERC20("DoubleEntryPointToken", "DET"), DelegateERC20, Ownable {
    address public cryptoVault;
    address public player;
    address public delegatedFrom;
    Forta public forta;

    constructor(address legacyToken, address vaultAddress, address fortaAddress, address playerAddress) {
        delegatedFrom = legacyToken;
        forta = Forta(fortaAddress);
        player = playerAddress;
        cryptoVault = vaultAddress;
        _mint(cryptoVault, 100 ether);
    }

    modifier onlyDelegateFrom() {
        require(msg.sender == delegatedFrom, "Not legacy contract");
        _;
    }

    modifier fortaNotify() {
        address detectionBot = address(forta.usersDetectionBots(player));

        // Cache old number of bot alerts
        uint256 previousValue = forta.botRaisedAlerts(detectionBot);

        // Notify Forta
        forta.notify(player, msg.data);

        // Continue execution
        _;

        // Check if alarms have been raised
        if (forta.botRaisedAlerts(detectionBot) > previousValue) revert("Alert has been triggered, reverting");
    }

    function delegateTransfer(address to, uint256 value, address origSender)
        public
        override
        onlyDelegateFrom
        fortaNotify
        returns (bool)
    {
        _transfer(origSender, to, value);
        return true;
    }
}
```

<details>
  <summary> Solution Explanation </summary>

- The LegacyToken (LGT) can delegate its transfer functionality to another contract (in this case, DoubleEntryPoint).
- When a transfer is attempted through LegacyToken and delegate is set, it calls delegateTransfer in DoubleEntryPoint.
- The sweepToken function is designed to transfer any tokens (other than underlying) held by the vault to a designated recipient.
- If LegacyToken is swept, it triggers a call to delegateTransfer, which performs the transfer and potentially circumvents restrictions in the vault.
- This modifier triggers Forta’s detection bot for each delegateTransfer call, allowing bots to detect and prevent unauthorized actions.


To protect the CryptoVault from being drained, we need to implement a Forta detection bot that:

- Monitors delegateTransfer calls to detect unauthorized CryptoVault token sweeps.
- Raises an alert whenever CryptoVault is the origSender in delegateTransfer, as this indicates an attempted sweep that could drain the vault.

Bot should decode the msgData to extract the parameters of the delegateTransfer function, check if origSender matches cryptoVault, indicating that CryptoVault initiated this transfer, which is the pattern of a token sweep. If this is the case, it raises an alert via Forta, stopping the transaction and preventing the sweep.

```solidity
   function handleTransaction(address, bytes calldata msgData) external override {
        (address to, uint256 value, address origSender) = abi.decode(msgData[4:], (address, uint256, address));
        if (origSender == cryptoVault) {
            IForta(msg.sender).raiseAlert(tx.origin);
        }
    }

```

</details>
_________________

## Good Samaritan

### Task: 

This instance represents a Good Samaritan that is wealthy and ready to donate some coins to anyone requesting it.

Would you be able to drain all the balance from his Wallet?

```solidity

// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "openzeppelin-contracts-08/utils/Address.sol";

contract GoodSamaritan {
    Wallet public wallet;
    Coin public coin;

    constructor() {
        wallet = new Wallet();
        coin = new Coin(address(wallet));

        wallet.setCoin(coin);
    }

    function requestDonation() external returns (bool enoughBalance) {
        // donate 10 coins to requester
        try wallet.donate10(msg.sender) {
            return true;
        } catch (bytes memory err) {
            if (keccak256(abi.encodeWithSignature("NotEnoughBalance()")) == keccak256(err)) {
                // send the coins left
                wallet.transferRemainder(msg.sender);
                return false;
            }
        }
    }
}

contract Coin {
    using Address for address;

    mapping(address => uint256) public balances;

    error InsufficientBalance(uint256 current, uint256 required);

    constructor(address wallet_) {
        // one million coins for Good Samaritan initially
        balances[wallet_] = 10 ** 6;
    }

    function transfer(address dest_, uint256 amount_) external {
        uint256 currentBalance = balances[msg.sender];

        // transfer only occurs if balance is enough
        if (amount_ <= currentBalance) {
            balances[msg.sender] -= amount_;
            balances[dest_] += amount_;

            if (dest_.isContract()) {
                // notify contract
                INotifyable(dest_).notify(amount_);
            }
        } else {
            revert InsufficientBalance(currentBalance, amount_);
        }
    }
}

contract Wallet {
    // The owner of the wallet instance
    address public owner;

    Coin public coin;

    error OnlyOwner();
    error NotEnoughBalance();

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert OnlyOwner();
        }
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function donate10(address dest_) external onlyOwner {
        // check balance left
        if (coin.balances(address(this)) < 10) {
            revert NotEnoughBalance();
        } else {
            // donate 10 coins
            coin.transfer(dest_, 10);
        }
    }

    function transferRemainder(address dest_) external onlyOwner {
        // transfer balance left
        coin.transfer(dest_, coin.balances(address(this)));
    }

    function setCoin(Coin coin_) external onlyOwner {
        coin = coin_;
    }
}

interface INotifyable {
    function notify(uint256 amount) external;
}

```

<details>
  <summary> Solution Explanation </summary>


To drain all the balance from the GoodSamaritan contract, we can implement a strategy that leverages the existing error handling mechanism in the requestDonation() function. Here’s a detailed breakdown of how to achieve this:

Understanding the Exploit

1.	Execution Flow:
	-	When requestDonation() is called, it tries to donate 10 coins by invoking wallet.donate10(msg.sender).
	-	If the balance in the wallet is less than 10 coins, it triggers the NotEnoughBalance() error, which is caught by the catch block.
	-	In the catch block, transferRemainder(msg.sender) is called, transferring the remaining coins to the caller (the attacker in this case).
2.	Reverting with a Custom Error:
	-	The notify() function in the Coin contract can call an external contract’s notify() function if the destination is a contract.
	-	If this notify() function reverts with the NotEnoughBalance() error, it will cause the requestDonation() to go to the catch block.
3.	Condition for Exploit:
	-	To control the flow, our notify() function must revert only when the amount is greater than 10. This way, the donate10() function can execute properly, but if the notify() function receives a notification for an amount that is 10 or less, it should revert.

</details>
_________________

## Gatekeeper Three

### Task: 

Cope with gates and become an entrant.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleTrick {
    GatekeeperThree public target;
    address public trick;
    uint256 private password = block.timestamp;

    constructor(address payable _target) {
        target = GatekeeperThree(_target);
    }

    function checkPassword(uint256 _password) public returns (bool) {
        if (_password == password) {
            return true;
        }
        password = block.timestamp;
        return false;
    }

    function trickInit() public {
        trick = address(this);
    }

    function trickyTrick() public {
        if (address(this) == msg.sender && address(this) != trick) {
            target.getAllowance(password);
        }
    }
}

contract GatekeeperThree {
    address public owner;
    address public entrant;
    bool public allowEntrance;

    SimpleTrick public trick;

    function construct0r() public {
        owner = msg.sender;
    }

    modifier gateOne() {
        require(msg.sender == owner);
        require(tx.origin != owner);
        _;
    }

    modifier gateTwo() {
        require(allowEntrance == true);
        _;
    }

    modifier gateThree() {
        if (address(this).balance > 0.001 ether && payable(owner).send(0.001 ether) == false) {
            _;
        }
    }

    function getAllowance(uint256 _password) public {
        if (trick.checkPassword(_password)) {
            allowEntrance = true;
        }
    }

    function createTrick() public {
        trick = new SimpleTrick(payable(address(this)));
        trick.trickInit();
    }

    function enter() public gateOne gateTwo gateThree {
        entrant = tx.origin;
    }

    receive() external payable {}
}

```
<details>
  <summary> Solution Explanation </summary>


1. Gate One:
	-	Must be called by the owner (the address that deployed GatekeeperThree).
	-	tx.origin must not be the owner.
2.	Gate Two:
	-	allowEntrance must be true.
3.	Gate Three:
	-	The balance of the contract must be greater than 0.001 ether, and the contract must fail when trying to send 0.001 ether to the owner.



We need to create a new instance of SimpleTrick by calling the createTrick() function in GatekeeperThree. This will allow us to interact with the gates.

After deploying the SimpleTrick contract, the password can be found in the storage of the SimpleTrick contract. We can use the web3.eth.getStorageAt method to fetch it.

With the retrieved password, we call the getAllowance function to set allowEntrance to true.

To meet the requirement of gate three, we need to send slightly more than 0.001 ether (i.e., 0.0011 ether) to the GatekeeperThree contract.

To fulfill the conditions of gate one, we can create a new contract that becomes the owner of the GatekeeperThree contract and does not accept ether. 

Deploying the Entrant contract and calling the enter() function we can become an entrant.

</details>
_________________

## Switch

### Task: 

Just have to flip the switch. Can't be that hard, right?

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Switch {
    bool public switchOn; // switch is off
    bytes4 public offSelector = bytes4(keccak256("turnSwitchOff()"));

    modifier onlyThis() {
        require(msg.sender == address(this), "Only the contract can call this");
        _;
    }

    modifier onlyOff() {
        // we use a complex data type to put in memory
        bytes32[1] memory selector;
        // check that the calldata at position 68 (location of _data)
        assembly {
            calldatacopy(selector, 68, 4) // grab function selector from calldata
        }
        require(selector[0] == offSelector, "Can only call the turnOffSwitch function");
        _;
    }

    function flipSwitch(bytes memory _data) public onlyOff {
        (bool success,) = address(this).call(_data);
        require(success, "call failed :(");
    }

    function turnSwitchOn() public onlyThis {
        switchOn = true;
    }

    function turnSwitchOff() public onlyThis {
        switchOn = false;
    }
}

```
<details>
  <summary> Solution Explanation </summary>

To “flip the switch” in the provided Solidity contract, we can exploit the flipSwitch function using a carefully crafted call to turnSwitchOn() through the _data parameter. The contract’s design allows us to invoke a function on itself using the call method, while the onlyOff modifier restricts the invocation to only the turnSwitchOff() function.


To flip the switch, we need to pass the selector of the turnSwitchOn() function in a way that the flipSwitch function can execute it.

```solidity
bytes4 public onSelector = bytes4(keccak256("turnSwitchOn()"));
```

The flipSwitch function requires the function signature to be the first four bytes of the _data parameter.

The final payload sent to flipSwitch must start with the function selector for turnSwitchOn() followed by the necessary padding (in this case, it can be all zeros).

The format for dynamic data types includes the length of the data followed by the actual data. For a static function with no parameters, we can just send the selector.

```jsx
functionSignature = {
    name: 'flipSwitch',
    type: 'function',
    inputs: [
           {
            type: 'bytes',
            name: '_data'
           }
         ]
    }
exp = web3.eth.abi.encodeFunctionSignature("explode()")
params = ['0x20606e15']
data = web3.eth.abi.encodeFunctionCall(functionSignature, params)
await web3.eth.sendTransaction({from: '0xDAc70eD79011695F414E18474868C0cDC808B493', to: implAddr, data})
```

0x30c13ade0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000020606e1500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000476227e1200000000000000000000000000000000000000000000000000000000

</details>
_________________

## HigherOrder

### Task: 

Imagine a world where the rules are meant to be broken, and only the cunning and the bold can rise to power. Welcome to the Higher Order, a group shrouded in mystery, where a treasure awaits and a commander rules supreme.

Your objective is to become the Commander of the Higher Order! Good luck!

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;

contract HigherOrder {
    address public commander;

    uint256 public treasury;

    function registerTreasury(uint8) public {
        assembly {
            sstore(treasury_slot, calldataload(4))
        }
    }

    function claimLeadership() public {
        if (treasury > 255) commander = msg.sender;
        else revert("Only members of the Higher Order can become Commander");
    }
}
```

<details>
  <summary> Solution Explanation </summary>

The probleme here it's the compiler's version which allows overflows.

The claimLeadership() function allows a caller to become the commander if the treasury is greater than 255. However, since the function signature accepts a uint8, the maximum value we can send directly is 255. Instead, we need to manipulate the storage directly via the assembly function. We can bypass the limitations of the uint8 type by sending a uint256 value directly to the storage slot using assembly.

```solidity
    assembly {
        sstore(HigherOrder.treasury.slot, 256)
    }
    HigherOrder.claimLeadership();
```


</details>
_________________

## Stake

### Task: 

Stake is safe for staking native ETH and ERC20 WETH, considering the same 1:1 value of the tokens. Can you drain the contract?

To complete this level, the contract state must meet the following conditions:

The Stake contract's ETH balance has to be greater than 0.
totalStaked must be greater than the Stake contract's ETH balance.
You must be a staker.
Your staked balance must be 0.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Stake {

    uint256 public totalStaked;
    mapping(address => uint256) public UserStake;
    mapping(address => bool) public Stakers;
    address public WETH;

    constructor(address _weth) payable{
        totalStaked += msg.value;
        WETH = _weth;
    }

    function StakeETH() public payable {
        require(msg.value > 0.001 ether, "Don't be cheap");
        totalStaked += msg.value;
        UserStake[msg.sender] += msg.value;
        Stakers[msg.sender] = true;
    }
    function StakeWETH(uint256 amount) public returns (bool){
        require(amount >  0.001 ether, "Don't be cheap");
        (,bytes memory allowance) = WETH.call(abi.encodeWithSelector(0xdd62ed3e, msg.sender,address(this)));
        require(bytesToUint(allowance) >= amount,"How am I moving the funds honey?");
        totalStaked += amount;
        UserStake[msg.sender] += amount;
        (bool transfered, ) = WETH.call(abi.encodeWithSelector(0x23b872dd, msg.sender,address(this),amount));
        Stakers[msg.sender] = true;
        return transfered;
    }

    function Unstake(uint256 amount) public returns (bool){
        require(UserStake[msg.sender] >= amount,"Don't be greedy");
        UserStake[msg.sender] -= amount;
        totalStaked -= amount;
        (bool success, ) = payable(msg.sender).call{value : amount}("");
        return success;
    }
    function bytesToUint(bytes memory data) internal pure returns (uint256) {
        require(data.length >= 32, "Data length must be at least 32 bytes");
        uint256 result;
        assembly {
            result := mload(add(data, 0x20))
        }
        return result;
    }
}
```

<details>
  <summary> Solution Explanation </summary>

To drain the Stake contract, we need to ensure the following:

1.	The Stake contract’s ETH balance is greater than 0.
2.	totalStaked must be greater than the Stake contract’s ETH balance.
3.	We must be a staker (i.e., our address is in Stakers).
4.	Our staked balance (UserStake[msg.sender]) must be 0.


So we need:
-	Become a Staker: First, we need to stake some ETH greater than 0.001 ether, and then we will immediately unstake it to ensure our balance is 0.
-	Manipulate Staked Amount: By calling the StakeWETH function, we can create a situation where we claim to have staked WETH tokens, updating the totalStaked variable without actually transferring any tokens due to the missing return value check.
- 	Drain the Contract: After successfully staking WETH (which we won’t actually have), we can call the Unstake function to drain the contract of its ETH.


```solidity

   function attack() external payable {
        // Step 1: Stake some ETH to become a staker
        require(msg.value > 0.001 ether, "Send more ETH to stake.");
        
        // Assume we already called StakeETH in the previous step
        
        // Step 2: Stake WETH without actually having it
        uint256 fakeWETHAmount = 1000 ether; // Fake amount for demonstration
        stakeContract.StakeWETH(fakeWETHAmount);

        // Step 3: Now attempt to unstake ETH
        stakeContract.Unstake(msg.value);
    }

```

</details>
