import Cryptography

@main
struct Main {
	static func main() async throws {
		let text = Array("123456".utf8)
		let key = Array("hello".utf8)
        print(key)
		let encryptor = SymmetricEncryptor(
			key: key, mode: EncryptionMode.ecb, padding: PaddingMode.zeros, iv: nil, args: [])!
		let encrypted = try await encryptor.encrypt(data: text)
        let decrypted = try await encryptor.decrypt(data: encrypted)
        print("encrypted = '\(encrypted)'")
        print("decrypted = '\(decrypted)'")
        print("original  = '\(text)'")
	}
}
