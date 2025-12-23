public actor Feistel: Encryptor {
	let expander: KeyExpander
	let transposer: EncryptTransposer
	var encrypt_keys: [Block]?
	var decrypt_keys: [Block]?

	public init(expander: KeyExpander, transposer: EncryptTransposer) throws {
		self.expander = expander
		self.transposer = transposer
	}

	public func setKey(key: Block) async throws {
		self.encrypt_keys = try await expander.expandKey(key: key)
		self.decrypt_keys = encrypt_keys!.reversed()
	}

	public func encrypt(data: Block) async throws -> Block {
		return try await self.transpose(data: data, keys: encrypt_keys, encrypt: true)
	}

	public func decrypt(data: Block) async throws -> Block {
		return try await self.transpose(data: data, keys: decrypt_keys, encrypt: false)
	}

	func transpose(data: Block, keys: [Block]?, encrypt: Bool) async throws -> Block {

		guard let keys = keys else {
			throw EncryptionError.keyNotSet
		}
		guard data.count % 2 == 0 else {
			throw EncryptionError.blockSize(data.count, "Blocks must be dividable in two")
		}
		let data = try transposer.preProcess(data: data, encrypt: encrypt)

		let middle = data.count / 2
		var left = Array(data[..<middle])
		var right = Array(data[middle...])
		for key in keys {
			var x = try await transposer.transpose(data: right, key: key)
			x ^= left
			left = right
			right = x
		}
		return try transposer.postProcess(data: right + left, encrypt: encrypt)
	}

	private init(
		expander: KeyExpander, transposer: EncryptTransposer, encrypt_keys: [Block]?,
		decrypt_keys: [Block]?
	) {
		self.expander = expander
		self.transposer = transposer
		self.encrypt_keys = encrypt_keys
		self.decrypt_keys = decrypt_keys
	}

	public func blockSize() async -> Int? { return self.transposer.blockSize() }
	public func keySizes() async -> [Int]? { return self.expander.keySizes() }
	public func duplicate() async -> Self {
		return Self(
			expander: self.expander, transposer: self.transposer, encrypt_keys: self.encrypt_keys,
			decrypt_keys: self.decrypt_keys)
	}
}
