import BigInt
import Testing

@testable import Crypto

@Suite("twoFish")
struct TwofishTests {
	@Test("Compare with online twofish encryptor")
	func twofishTestExpected() async throws {
		let key = Array("1234567887654321".utf8)
		let plaintext = Array("hello from twofish encryptor".utf8)
		let expected = "8ad8ef63241e1ff46c2c57e6a23028d154d515cf61c5ade67a6ef0fdc733c962"
		let cipher = try await SymmetricEncryptor(
			encryptor: TwofishEncryptor(), key: key, mode: EncryptionMode.ecb,
			padding: PaddingMode.zeros,
			iv: nil, args: [])
		let encr = try await cipher.encrypt(data: plaintext)
		#expect(encr.toHexString() == expected)
	}
	@Test("Twofish encryption", arguments: [16, 24, 32])
	func twofishTestComprehensive(size: Int) async throws {
		let key = Array.random(size: size)
		let cipher = try await SymmetricEncryptor(
			encryptor: TwofishEncryptor(),
			key: key, mode: EncryptionMode.ecb, padding: PaddingMode.zeros, iv: nil,
			args: [])
		for n in (1...10) {
			var data = Array.random(size: n * 60)
			try cipher.unpadData(data: &data)
			let encr = try await cipher.encrypt(data: data)
			let res = try await cipher.decrypt(data: encr)
			#expect(res == data, "\(data) with \(key)")
		}
	}
}
