import Testing

@testable import Cryptography

@Test("Test general") func testBitOperations() async throws {
	var a: UInt8 = 0
	a[1] = true
	#expect(a == 2)
	a[7] = true
	#expect(a == 130)
}

@Test("Test 1.1") func testTransposition() async throws {
	let values: [UInt8] = [1, 2, 3, 4, 5, 6]
	var cipher = [7, 6, 5, 4, 3, 2, 1, 0]
	var res = Cryptography.transpose(
		data: values, rule: cipher, order: BitOrder.forward,
		firstBit: FirstBitIndex.zero)

	#expect(res != nil)
	#expect(res! == [128, 64, 192, 32, 160, 96])

	res = Cryptography.transpose(
		data: values, rule: cipher, order: BitOrder.backward,
		firstBit: FirstBitIndex.zero)

	#expect(res != nil)
	#expect(res! == [1, 2, 3, 4, 5, 6])

	cipher = [8, 7, 6, 5, 4, 3, 2, 1]

	res = Cryptography.transpose(
		data: values, rule: cipher, order: BitOrder.backward,
		firstBit: FirstBitIndex.one)

	#expect(res != nil)
	#expect(res! == [1, 2, 3, 4, 5, 6])
}

@Suite("Test 1.2")
struct Test12 {
	@Test(
		"1.2 padding", arguments: PaddingMode.allCases,
		["12345678", "Hello, World"])
	func testPadding(padding: PaddingMode, key: String) async throws {

		if padding == PaddingMode.ansiX923 && key.count > 8 {
			return
		}

		let cipher = SymmetricEncryptor(
			key: Array(key.utf8), mode: EncryptionMode.ecb, padding: padding, iv: nil, args: [])!
		for n in (1...32) {
			let str: String = (1...n).reduce(
				"", { partialResult, val in partialResult + " " + String(val) })
			let data = Array(str.utf8)
			let padded = cipher.padData(data: data).joined()
			var res = Array(padded)
			try cipher.unpadData(data: &res)
			let newString = String(decoding: res, as: UTF8.self)
			#expect(data == res)
			if str != newString {
				return
			}
		}
	}

	@Test(
		"1.2 encryption", arguments: PaddingMode.allCases,
		[EncryptionMode.ecb, EncryptionMode.cbc])
	func testEncryption(padding: PaddingMode, mode: EncryptionMode) async throws {
		let key = "12345678"
		let iv = "abcdefgh"
		for n in (1...32) {
			let cipher = SymmetricEncryptor(
				key: Array(key.utf8), mode: mode, padding: padding, iv: Array(iv.utf8), args: [])!
			let str: String = (1...n).reduce(
				"", { partialResult, val in partialResult + " " + String(val) })
			let data = Array(str.utf8)
			let encr = try await cipher.encrypt(data: data)
			let res = try await cipher.decrypt(data: encr)
			let newString = String(decoding: res, as: UTF8.self)
			#expect(res == data, "\(str)")
			if str != newString {
				return
			}
		}

	}
}
