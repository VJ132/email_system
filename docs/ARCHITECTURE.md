****# Architecture Design For An Encrypted Transport

## Header Structure

- `[2 Bytes Fragment Length][12 Bytes Fragment Nonce][Fragment Data][16 Bytes Fragment Tag]`
- Each fragment can hold data upto $2^{16} - 1$ bits of data.
- A fragment can be a whole message or a message that is fragmented.
