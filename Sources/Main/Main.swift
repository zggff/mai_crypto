import Symmetric
import Aes

@main
struct Main {
	static func main() async throws {
		let key = Array("1234567887654321".utf8)
		let aes = try await AesEncryptor(key: key, keySize: 16, blockSize: 16, irreducible: 283)
		let cipher = try SymmetricEncryptor(
			encryptor: aes,
			key: key, mode: EncryptionMode.ecb, padding: PaddingMode.zeros, iv: nil,
			args: [])
		let str = "1"
		let data = Array(str.utf8)
		let encr = try await cipher.encrypt(data: data)
        print(encr.toHexString())
	}
}
