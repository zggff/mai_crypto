public final class Feistel<K: KeyExpander, T: EncryptTransposer>: Encryptor {
	let expander: KeyExpander
	let transposer: EncryptTransposer
	let encrypt_keys: [Block]
	let decrypt_keys: [Block]

	public init(key: Block) throws {
		self.expander = K()
		self.transposer = T()
		self.encrypt_keys = try expander.expandKey(key: key)
		self.decrypt_keys = encrypt_keys.reversed()
	}

	public func encrypt(data: Block) throws -> Block {
		return try self.transpose(data: data, keys: encrypt_keys)
	}

	public func decrypt(data: Block) throws -> Block {
		return try self.transpose(data: data, keys: decrypt_keys)
	}

	func transpose(data: Block, keys: [Block]) throws -> Block {
		guard data.count % 2 == 0 else {
			throw EncryptionError.blockSize(data.count, "Blocks must be dividable in two")
		}
		let data = try transposer.preProcess(data: data)

		let middle = data.count / 2
		var left = Array(data[..<middle])
		var right = Array(data[middle...])
		for key in keys {
			var x = try transposer.transpose(data: right, key: key)
			x ^= left
			left = right
			right = x
		}
		return try transposer.postProcess(data: right + left)
	}
}
