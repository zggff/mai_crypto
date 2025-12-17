import Testing

@testable import Crypto

@Suite("Test des")
struct TestDes {
	@Test("Test general") func testBitOperations() async throws {
		var a: UInt8 = 0
		a[1] = true
		#expect(a == 2)
		a[7] = true
		#expect(a == 130)
	}

	@Test("Adding Int to [UInt8]")
	func test_into_to_uint8_array_adding() {
		for i in stride(from: 0, to: 2048, by: 10) {
			for j in stride(from: 0, to: 2048, by: 10) {
				var arr: [UInt8] = Array(repeating: 0, count: 4)
				arr += i
				arr += j
				let b = arr.reduce(0) { soFar, byte in
					return soFar << 8 | UInt32(byte)
				}
				#expect(i + j == b, "\(i) + \(j) = \(i + j), \(arr), \(b)")
				guard i + j == b else {
					return
				}
			}
		}
	}

	@Test(
		"test padding", arguments: PaddingMode.allCases,
		["12345678", "Hello, World"])
	func testPadding(padding: PaddingMode, key: String) async throws {

		if padding == PaddingMode.ansiX923 && key.count > 8 {
			return
		}

		let cipher = try await SymmetricEncryptor(
			encryptor: AddEncryptor(key: Array(key.utf8)),
			key: Array(key.utf8), mode: EncryptionMode.ecb, padding: padding, iv: nil, args: [])
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

	actor AddEncryptor: Encryptor {
		func setKey(key: Block) async throws {
			self.key = key
		}

		var key: Block
		init(key: Block) throws {
			self.key = key
		}
		func encrypt(data: Block) throws -> Block {
			var new_data = data
			new_data += key
			return new_data
		}
		func decrypt(data: Block) throws -> Block {
			var new_data = data
			new_data -= key
			return new_data
		}
		func keySizes() async -> [Int]? {
			return nil
		}
		func blockSize() async -> Int? {
			return nil
		}

	}

	@Test(
		"test block modes", arguments: PaddingMode.allCases,
		EncryptionMode.allCases
	)
	func testEncryption(padding: PaddingMode, mode: EncryptionMode) async throws {
		let key = "12345678"
		let iv = "abcdefgh"
		for n in (1...32) {
			let cipher = try await SymmetricEncryptor(
				encryptor: AddEncryptor(key: Array(key.utf8)),
				key: Array(key.utf8), mode: mode, padding: padding, iv: Array(iv.utf8), args: []
			)
			let str: String = (1...n).reduce(
				"", { partialResult, val in partialResult + " " + String(val) })
			let data = Array(str.utf8)
			let encr = try await cipher.encrypt(data: data)
			let res = try await cipher.decrypt(data: encr)
			let newString = String(decoding: res, as: UTF8.self)
			#expect(res == data, "\(str) with \(mode) + \(padding)")
			if str != newString {
				return
			}
		}

	}

	// https://emn178.github.io/online-tools/des/encrypt/
	@Test("DES encryption as example")
	func desTest() async throws {
		let key = Array("12345678".utf8)
		let text = Array("Lorem ipsum dolor".utf8)
		let des = try Feistel(expander: DesExpander(), transposer: DesTransposer())
		let encryptor = try await SymmetricEncryptor(
			encryptor: des,
			key: key, mode: EncryptionMode.ecb, padding: PaddingMode.zeros, iv: nil,
			args: [])
		let encrypted = try await encryptor.encrypt(data: text)
		#expect(
			encrypted.toHexString() == "b959cd9089fd2e4e59a8ce28b00a7320a8829ecfa5805c33",
			"must be the same as in example")
	}
	@Test("DES encryption")
	func desTestComprehensive() async throws {
		let key = Array("12345678".utf8)
		let des = try Feistel(expander: DesExpander(), transposer: DesTransposer())
		let cipher = try await SymmetricEncryptor(
			encryptor: des,
			key: key, mode: EncryptionMode.ecb, padding: PaddingMode.zeros, iv: nil,
			args: [])
		for n in (1...32) {
			let str: String = (1...n).reduce(
				"", { partialResult, val in partialResult + " " + String(val) })
			let data = Array(str.utf8)
			let encr = try await cipher.encrypt(data: data)
			let res = try await cipher.decrypt(data: encr)
			let newString = String(decoding: res, as: UTF8.self)
			#expect(res == data, "\(str) with feistel")
			if str != newString {
				return
			}
		}
	}
	@Test("Deal encryption", arguments: [16, 24, 32])
	func dealTestComprehensive(size: Int) async throws {
		let key = Array.random(size: size)
		let deal = try Feistel(expander: DealExpander(), transposer: DealTransposer())
		let cipher = try await SymmetricEncryptor(
			encryptor: deal,
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
