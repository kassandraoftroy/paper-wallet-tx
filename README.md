# paper-wallet-tx

Bitcoin paper wallets and brain wallets are no longer recommended for use by the bitcoin community for a number of reasons ([see here](https://en.bitcoin.it/wiki/Address_reuse) or [here](https://www.coindesk.com/brainwallet-bitcoin-wallet-shouldnt-use))

However, there are certain situations where a brain wallet still may be convenient, as well as legacy paper/brain wallets that still need to be managed or swept into a modern wallet client.

This is a tool to help those bitcoin paper wallets that currently exist to move their bitcoins with a simple python script.

IMPORTANT: For simplicity this tool only supports P2PKH transactions, meaning transactions to/from bitcoin addresses that begin with a "1"

## Install

Requires python3

1. Clone or download this repository.

2. Enter the root directory ( `cd paper-wallet-tx` )

3. Install dependencies with `pip3 install -r requirements.txt`

## Usage

This tool only supports two simple operations `sweep` and `send`

Both commands are similar in that they prompt the user for the transaction details (most importantly the WIF private key from the paper wallet)
and return raw hexadecimal transaction hex that can be pushed to the blockchain (e.g. [here](https://www.blockchain.com/btc/pushtx))

**Sweep**

Sweep is the most canonical thing to do with a paper wallet. Send the entire 'balance' of the paper wallet to a target address, completely draining the wallet. This is the simplest way to take coins from a paper wallet and move them to a better / more contemporary wallet that you control. The target address needs to be a simple P2PKH address (must begin with a "1").

run this command with:

`python3 paperwallet.py sweep`

you will be prompted for the receiving address and your private key (WIF format)

on success the script returns raw hexadecimal bytes of your signed transaction


**Send**

Send allows you to send a specific amount from your paper wallet. This is not usually recommended (sweep a paper wallet instead, and then do your transactions from a modern wallet). It's here in case someone really needs to spend a specific amount from a paper wallet. If you leave the change address blank, the change from the transaction will be sent back to the paper wallet. This is an unrecommended practice of address reuse, but it's better than losing the change to the miners! You can also set the change address to another P2PKH address that you control, which is a better practice.

run this command with:

`python3 paperwallet.py send`

you will be prompted for 
- receiving address
- amount to send in BTC (i.e. 0.5)
- private key (WIF format)
- change address (where leftover transaction outputs get sent)

on success the script returns raw hexadecimal bytes of your signed transaction