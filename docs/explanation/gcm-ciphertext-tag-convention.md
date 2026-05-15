# The `ciphertext || tag` GCM convention

**Surprise.** `Cipher.doFinal()` on AES-GCM returns *16 more bytes than the plaintext input*. On decrypt,
those 16 bytes must be appended to the ciphertext.

**Why.** GCM produces two outputs: ciphertext (same length as plaintext) and a 16-byte authentication tag.
JCA's `Cipher` API has only one return slot for `doFinal()`,
so the standard convention is to **append the tag to the ciphertext**:

```
JCA encrypt output = ciphertext (n bytes) || tag (16 bytes)
JCA decrypt input  = ciphertext (n bytes) || tag (16 bytes)
```

Every JCA GCM provider behaves this way (SunJCE, BouncyCastle, this provider).

**On the wire the proto splits them.** `EncryptResponse` carries `ciphertext` and `tag` as separate fields.
`HsmAesGcmCipherSpi` re-bundles them on the way out and splits them off on the way in — so callers see standard
JCA behaviour while the HSM Proxy sees the explicit split the proto requires.

**Practical consequence.** Stored ciphertext from this provider has the layout `ct || tag`.
To decrypt later, pass that combined blob plus the IV — nothing else needed.
