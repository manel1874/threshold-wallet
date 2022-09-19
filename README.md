
This is a simple prototype of an Ethereum crypto wallet that uses [ZenGo-X implementation](https://github.com/ZenGo-X/multi-party-ecdsa) of {t,n}-Threshold ECDSA based on the [GG20](https://eprint.iacr.org/2020/540.pdf) algorithm. We point to their [Binance academy article](https://www.binance.vision/security/threshold-signatures-explained) for an exmplanation of threshold signatures.

The prototype has the following features:
- For every wallet, n key shares are generated.
- Any n-t out of the n shares can sign a transaction.
- A private key is never generated to create a new wallet.
- The private key doesn’t need to be reconstructed to sign a transaction.
\end{enumerate}



# Installation

1. Install ZenGo-X implementation in your Home directory.

- Install [Rust](https://rustup.rs/)
- Install [GMP](https://gmplib.org/) library (optionally)
- Build the project:

```
cargo build --release --examples
```

For further guidance we refer to ZenGo-X [library](https://github.com/ZenGo-X/multi-party-ecdsa).


2. Install Python dependencies

Python version: 3.5.* and above.

```
pip install pycryptodome pycoin nummaster Flask==1.1.4
```

3. Clone this repo.

# Run prototype

- Inside the threshold-wallet main folder run:
```
python webapp.py
```

- Open your browser at http://127.0.0.1:5000/

## Demo

You can see a demo on [YouTube](https://youtu.be/_1OWxtxJ8ZY).

