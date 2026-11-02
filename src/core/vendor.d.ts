/** Minimal ambient typings for the two vendored CJS crypto modules.
 * aes-js ships no declarations in this install; des.js never had any. Only
 * the surfaces the core actually touches are declared. */

declare module 'aes-js' {
  interface EcbBlockMode {
    encrypt(data: Uint8Array): Uint8Array
    decrypt(data: Uint8Array): Uint8Array
  }
  interface AesJs {
    ModeOfOperation: {
      ecb: new (key: Uint8Array) => EcbBlockMode
    }
  }
  const aesjs: AesJs
  export = aesjs
}

declare module 'des.js' {
  interface BlockCipherOptions {
    type: 'encrypt' | 'decrypt'
    key: Uint8Array
    padding: false
  }
  interface BlockCipher {
    update(data: Uint8Array): number[] | Uint8Array
    final(): number[] | Uint8Array
  }
  interface DesModule {
    DES: new (options: BlockCipherOptions) => BlockCipher
    EDE: new (options: BlockCipherOptions) => BlockCipher
  }
  const des: DesModule
  export = des
}
