public final class Feistel: Encryptor {
	let expander: KeyExpander
	let transposer: EncryptTransposer
	let encrypt_keys: [Block]
	let decrypt_keys: [Block]

	public init(key: Block, expander: KeyExpander, transposer: EncryptTransposer) async throws {
		self.expander = expander
		self.transposer = transposer
        self.encrypt_keys = try await expander.expandKey(key: key)
		self.decrypt_keys = encrypt_keys.reversed()

	}

    public init(expander: KeyExpander, transposer: EncryptTransposer) throws {
		self.expander = expander
		self.transposer = transposer
        self.encrypt_keys = []
        self.decrypt_keys = []
	}

    public func setKey(key: Block) async throws -> Self {
        return try await Self(key: key, expander: self.expander, transposer: self.transposer)
    }

	public func encrypt(data: Block) async throws -> Block {
		return try await self.transpose(data: data, keys: encrypt_keys, encrypt: true)
	}

	public func decrypt(data: Block) async throws -> Block {
		return try await self.transpose(data: data, keys: decrypt_keys, encrypt: false)
	}

	func transpose(data: Block, keys: [Block], encrypt: Bool) async throws -> Block {
        guard keys.count > 0 else {
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

    public func blockSize() -> Int? {return self.transposer.blockSize()}
    public func keySizes() -> [Int]? {return self.expander.keySizes()}
}
