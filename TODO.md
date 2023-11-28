1. Refactor ZenGo codes depended by gg18, especially replace `Vec<T>` with `HashMap<usize, T>`.
    * Identify `curv-kzen, kzen-paillier, multi-party-ecdsa` codes used by `keygen, keygen-mnem, sign`.
    * Collect their ground-truth inputs and outputs.
    * Mock these functions, replace almost every `Vec<T>` to `HashMap<usize, T>`
2. Add batch sign
3. Add reshare
4. Add range proof
5. Change to nested shamir