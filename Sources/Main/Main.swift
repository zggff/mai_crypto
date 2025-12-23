import BigInt
import Crypto
import Foundation

struct Main {
	static func main() async throws {
		let aes = try await AesEncryptor(keySize: 16, blockSize: 16)
		try await aes.setKey(key: Array("1234567887654321".utf8))
		// print(GF256.irreducible(0b1111))
		// print(GF256.degree(0b1111))
	}
}

@main
struct Main2 {
	static func main() async throws {
        let key_size = 32
        let block_size = 32
		let key = Array.random(size: key_size)
		let aes = try await AesEncryptor(keySize: key_size, blockSize: block_size, irreducible: 283)
		let cipher = try await BlockEncryptor(
			encryptor: aes,
			key: key, mode: .ecb, padding: .zeros, iv: nil,
			args: [])
		for n in (1...10) {
			var data = Array.random(size: n * 60)
			let encr = try await cipher.encrypt(data: data)
			let res = try await cipher.decrypt(data: encr)
			break
		}

	}
}
