# bip119

Minimal support for [BIP-119 CHECKTEMPLATEVERIFY](https://github.com/bitcoin/bips/tree/master/bip-0119.mediawiki).
This crate is intended to serve as a reusable component for building applications with CTV in a way that should be perpetually nearly ready to merge into [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) if CTV is activated.
It may initially evolve rapidly according to feedback from `rust-bitcoin`, but is intended to be drop-in-replaced by official support in `rust-bitcoin` eventually.
