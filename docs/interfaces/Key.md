# Interface: Key

A minimal key representation interface.

This interface is designed to be compatible with Web Cryptography's CryptoKey objects while
allowing for custom key implementations that may not have all CryptoKey properties. It includes
only the essential properties needed for HPKE operations and validations.

## Contents

- [Properties](#properties)
  - [algorithm](#algorithm)
  - [extractable](#extractable)
  - [type](#type)

## Properties

### algorithm

> `readonly` **algorithm**: `object`

The key algorithm properties

#### name

> **name**: `string`

The algorithm identifier for the key.

***

### extractable

> `readonly` **extractable**: `boolean`

Whether the key material can be extracted.

***

### type

> `readonly` **type**: `"private"` ∣ `"public"`

The type of key: 'private' or 'public'
