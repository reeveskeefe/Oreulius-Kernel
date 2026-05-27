# Cryptography tests folder



Implementations under test (not assertions). Via checks the imported primitives that are copied from the kernels source code per verbatim. Then These are re-exported to the lib.rs in the root, and ran as a whole. This is to test are derivations are mathematically correct in order to help build trust with the community. Further testing of the crypto folder is now going to be done thorugh here, and documented in the crypto folders readme for future development. 

## Run These tests all at once. 

```bash
cargo test
```

Source: the src/crypto folder

_this crate keeps small, dependency-light copies so the cargo test command works on the host._
