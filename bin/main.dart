import 'package:steel_crypt/steel_crypt.dart';
import 'package:cryptography/cryptography.dart';
import 'package:convert/convert.dart';
import 'dart:convert';

final passCrypt = PassCrypt('SHA-256/HMAC/PBKDF2');
final salt = CryptKey().genDart(16);

Future<List<int>> longEncrypt(psw) async {

  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: 100000,
    bits: 128,
  );

  // Password we want to hash
  final secretKey = SecretKey(psw.codeUnits); //SecretKey([1,2,3]);

  // A random salt
  final nonce = [4,5,6];

  // Calculate a hash that can be stored in the database
  final newSecretKey = await pbkdf2.deriveKey(
    secretKey: secretKey,
    nonce: nonce,
  );
  final List<int> list = await newSecretKey.extractBytes();
  return list;
}

Future<String> encrypt(psw) async {
  List<int> encrypted = await longEncrypt(psw);
  return new String.fromCharCodes(encrypted);
}

verify(psw1, psw2, hashed) async {
  print("[VERIFY] $psw1\t$psw2");
  var isCorrect = await hash(psw1) == hashed;
  print("[VERIFY] $isCorrect");
}

Future<String> hash(psw) async {
  print("[HASH] plainPassword: $psw");
  psw = await encrypt(psw);
  var hashed = passCrypt.hashPass(salt, psw);
  print("[HASH] hashedPassword: $hashed");
  return hashed;
}

main() async {
  String psw1 = "pass1234";
  String psw2 = "1234pass";
  String hash1 = await hash(psw1);
  String hash2 = await hash(psw2);
  verify(psw1, psw2, hash2);
  verify(psw1, psw1, hash1);
}
