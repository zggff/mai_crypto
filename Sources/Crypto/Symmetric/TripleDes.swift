public struct TripleDes: Encryptor {
	private var des1: DesEncryptor
	private var des2: DesEncryptor
	private var des3: DesEncryptor
	private var mode: Mode

	private init(d1: DesEncryptor, d2: DesEncryptor, d3: DesEncryptor, m: Mode) {
		self.des1 = d1
		self.des2 = d2
		self.des3 = d3
		self.mode = m
	}

	public func clone() -> Self {
		return Self(d1: self.des1, d2: self.des2, d3: self.des3, m: self.mode)
	}

	public enum Mode: CaseIterable & Sendable {
		case ede
		case eee
	}

	public init(mode: Mode = .ede) {
		self.mode = mode
		self.des1 = DesEncryptor()
		self.des2 = DesEncryptor()
		self.des3 = DesEncryptor()
	}

	public mutating func setKey(key: Block) async throws {
		guard keySizes()!.contains(key.count) else {
			throw EncryptionError.keySize(key.count, "3DES key must be 16 or 24 bytes")
		}

		let key1 = Array(key[0..<8])
		let key2 = Array(key[8..<16])
		let key3 = key.count == 24 ? Array(key[16..<24]) : key1

		try await des1.setKey(key: key1)
		try await des2.setKey(key: key2)
		try await des3.setKey(key: key3)
	}

	public func encrypt(data: Block) async throws -> Block {
		switch mode {
			case .ede:
				let encrypted1 = try await des1.encrypt(data: data)
				let decrypted = try await des2.decrypt(data: encrypted1)
				let encrypted2 = try await des3.encrypt(data: decrypted)
				return encrypted2

			case .eee:
				let encrypted1 = try await des1.encrypt(data: data)
				let encrypted2 = try await des2.encrypt(data: encrypted1)
				let encrypted3 = try await des3.encrypt(data: encrypted2)
				return encrypted3
		}
	}

	public func decrypt(data: Block) async throws -> Block {
		switch mode {
			case .ede:
				let decrypted1 = try await des3.decrypt(data: data)
				let encrypted = try await des2.encrypt(data: decrypted1)
				let decrypted2 = try await des1.decrypt(data: encrypted)
				return decrypted2

			case .eee:
				let decrypted1 = try await des3.decrypt(data: data)
				let decrypted2 = try await des2.decrypt(data: decrypted1)
				let decrypted3 = try await des1.decrypt(data: decrypted2)
				return decrypted3
		}
	}

	public func blockSize() -> Int? {
		return 8
	}

	public func keySizes() -> [Int]? {
		return [16, 24]
	}
}
