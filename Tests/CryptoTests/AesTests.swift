import Testing

@testable import Aes
@testable import Symmetric

@Suite("Aes tests")
final class AesTests {
	@Test
	func testAddition() {
		#expect(GF256.add(0b1010_1010, 0b0101_0101) == 0b1111_1111)
		#expect(GF256.add(0b1111_0000, 0b1111_0000) == 0b0000_0000)
		#expect(GF256.add(0x57, 0x83) == 0xD4)

		for irr in GF256.allIrreducible() {
			#expect(GF256.factorPolynomial(irr).count == 1)
		}
	}

	@Test("AES encryption with example")
	func aesTestComprehensive() async throws {
		let key = Array("1234567887654321".utf8)
		let aes = try await AesEncryptor(keySize: 16, blockSize: 16, irreducible: 283)
		let cipher = try await SymmetricEncryptor(
			encryptor: aes,
			key: key, mode: EncryptionMode.ecb, padding: PaddingMode.zeros, iv: nil,
			args: [])
		let str = "This is an example of aes encryption"
		let data = Array(str.utf8)
		let encr = try await cipher.encrypt(data: data).toHexString().uppercased()
        #expect(encr == "CB47C2F07ED29D58466D279CE3E76988D5D37D1EA017BE5A902425B5E4BEC159D83763BBF5A929FAA7790B35B5F4F753")

	}
    @Test("Aes encryption", arguments: [16, 24, 32], [16, 24, 32])
	func aesTestComprehensive(key_size: Int, block_size: Int) async throws {
		let key = Array.random(size: key_size)
		let aes = try await AesEncryptor(keySize: key_size, blockSize: block_size, irreducible: 283)
		let cipher = try await SymmetricEncryptor(
			encryptor: aes,
			key: key, mode: EncryptionMode.ecb, padding: PaddingMode.zeros, iv: nil,
			args: [])
		for n in (1...10) {
			var data = Array.random(size: n * 60)
			try cipher.unpadData(data: &data)
			let encr = try await cipher.encrypt(data: data)
			let res = try await cipher.decrypt(data: encr)
			#expect(res == data, "\(data) with \(key)")
            break
		}
	}
}
