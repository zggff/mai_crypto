import Crypto

@main
struct Main {
	static func main() async throws {
		let key = Array("1234567887654321".utf8)

		let plaintext: [Byte] = Array("YELLOWSUBMARINES".utf8)

		let encryptor = TwofishEncryptor()
        try await encryptor.setKey(key: key)
		let ciphertext2 = try await encryptor.encrypt(data: plaintext)
		print("Ciphertext: \(ciphertext2.toHexString())")

		let decrypted2 = try await encryptor.decrypt(data: ciphertext2)
		print("Decrypted:  \(decrypted2.toHexString())")
		print("Decrypted:  \(plaintext.toHexString())")
		print("Match:      \(plaintext == decrypted2)")
	}
}
