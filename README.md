# Verifiable Secret Sharing (VSS)

Implementation of the [Verifiable Secret Sharing (VSS)][vss] in Go using Feldman's scheme.

Note that this scheme is, at best, secure against computationally bounded
adversaries, namely the intractability of computing discrete logarithms.

This package:

* supports splitting and recombining a *big.Int in the finite field of an
  elliptic curve;
* supports verifying shares given commitments produced by a dealer during
  split.

## License

This library is licences under [BSD 2-Clause License](LICENSE).

[vss]: https://en.wikipedia.org/wiki/Verifiable_secret_sharing
