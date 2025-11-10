# Interface: KeyPair

Represents a cryptographic key pair consisting of a public key and private key.

These keys are used throughout HPKE for key encapsulation mechanisms (KEM). Key pairs are
randomly generated using [CipherSuite.GenerateKeyPair](../classes/CipherSuite.md#generatekeypair) or deterministically derived from a
seed using [CipherSuite.DeriveKeyPair](../classes/CipherSuite.md#derivekeypair).

Key Usage:

- Public Key: Used by senders for encryption operations (passed to [CipherSuite.SetupSender](../classes/CipherSuite.md#setupsender)
  or [CipherSuite.Seal](../classes/CipherSuite.md#seal)). These keys are distributed by recipients.
- Private Key: Used by recipients for decryption operations (passed to
  [CipherSuite.SetupRecipient](../classes/CipherSuite.md#setuprecipient) or [CipherSuite.Open](../classes/CipherSuite.md#open)). These are not distributed and
  kept private.

## Contents

- [Properties](#properties)
  - [privateKey](#privatekey)
  - [publicKey](#publickey)

## Properties

### privateKey

> `readonly` **privateKey**: `Readonly`<[`Key`](Key.md)>

The private key, used for decryption operations.

***

### publicKey

> `readonly` **publicKey**: `Readonly`<[`Key`](Key.md)>

The public key, used for encryption operations.
