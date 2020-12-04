import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptoutils/utils.dart';

abstract class Key {}

/// For HS256 algorithm
class SecretKey extends Key {
  Uint8List key;

  get asString => utf8.decode(this.key, allowMalformed: true);
  get asHexString => CryptoUtils.bytesToHex(this.key);
  get asBase64 => CryptoUtils.bytesToBase64(this.key);

  static SecretKey fromString(String key) {
    List<int> _bytes = utf8.encode(key);
    return SecretKey(Uint8List.fromList(_bytes));
  }

  static SecretKey fromHex(String hexKey) {
    return SecretKey(CryptoUtils.hexToBytes(hexKey));
  }

  static SecretKey fromBase64(String b64Key) {
    return SecretKey(CryptoUtils.base64StringToBytes(b64Key));
  }

  SecretKey(this.key);
}

/// For RS256 algorithm, in sign method
class PrivateKey extends Key {
  String key;
  String passphrase;

  PrivateKey(this.key, [this.passphrase = '']);
}

/// For RS256 algorithm, in verify method
class PublicKey extends Key {
  String key;
  String passphrase;

  PublicKey(this.key, [this.passphrase = '']);
}
