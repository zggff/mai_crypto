import Darwin

public enum BitOrder {
	case forward
	case backward
}

public enum FirstBitIndex {
	case zero
	case one
}

public protocol KeyExpander: Sendable {
	init()
	func expandKey(key: Block) throws -> [Block]
	static func KEY_SIZES() -> [Int]?
}

extension KeyExpander {
	public static func KEY_SIZES() -> [Int]? {return nil}
}

public protocol EncryptTransposer: Sendable {
	init()
	func transpose(data: Block, key: Block) throws -> Block
	func preProcess(data: Block, encrypt: Bool) throws -> Block
	func postProcess(data: Block, encrypt: Bool) throws -> Block
	static func BLOCK_SIZE() -> Int?
}

extension EncryptTransposer {
	public static func BLOCK_SIZE() -> Int? {return nil}
}

extension EncryptTransposer {
	public func preProcess(data: Block, encrypt: Bool = true) throws -> Block { return data }
	public func postProcess(data: Block, encrypt: Bool = true) throws -> Block { return data }
}

public protocol Encryptor: Sendable {
	init(key: Block) throws
	func encrypt(data: Block) throws -> Block
	func decrypt(data: Block) throws -> Block
	static func BLOCK_SIZE() -> Int?
	static func KEY_SIZES() -> [Int]?
}

extension Encryptor {
	public static func BLOCK_SIZE() -> Int? { return nil }
	public static func KEY_SIZES() -> [Int]? { return nil }
}

public enum EncryptionMode: CaseIterable & Sendable {
	case ecb
	case cbc
	case pcbc
	case cfb
	case ofb
	case ctr
	case randomDelta
}

public enum PaddingMode: CaseIterable & Sendable {
	case zeros
	case ansiX923
	case pkcs7
	case iso10126
}

public enum EncryptionModeArg: Sendable {}

extension Array {
	public var lastMut: Element {
		get {
			return self[count - 1]
		}
		set {
			self[count - 1] = newValue
		}
	}
}

public typealias Block = [Byte]

extension Array {
	public func splitInSubArrays(into size: Int) -> [[Element]] {
		let cnt = (self.count - 1) / size + 1
		return (0..<cnt).map({ i in Array(self[i * size..<Swift.min(((i + 1) * size), self.count)])
		})
	}
}

public enum EncryptionError: Error {
	case notFitting
	case runtimeError(String)
	case blockSize(Int, String?)
	case keySize(Int, String?)
	case invalidPadding
	case outOfRange(Int, Int)
	case iv
}

public class SymmetricEncryptor {
	// let key: [Byte]
	let block_size: Int
	let mode: EncryptionMode
	let padding: PaddingMode
	let iv: [Byte]?
	let args: [EncryptionModeArg]
	let encryptor: any Encryptor

	public init(
		type: Encryptor.Type, key: [Byte], mode: EncryptionMode, padding: PaddingMode, iv: [Byte]?,
		args: [EncryptionModeArg]
	) throws {
		self.block_size = type.BLOCK_SIZE() ?? key.count
		self.mode = mode
		self.padding = padding
		self.iv = iv
		self.args = args
		if let key_sizes = type.KEY_SIZES() {
			if !key_sizes.contains(key.count) {
				throw EncryptionError.keySize(key.count, "key size must be one of \(key_sizes)")
			}

		}
		if let iv = iv {
			if iv.count != self.block_size {
				throw EncryptionError.iv
			}
		}
		if padding == PaddingMode.ansiX923 && block_size > 8 {
			throw EncryptionError.blockSize(key.count, "ansiX923 block must be <= 8 bytes")
		}

		self.encryptor = try type.init(key: key)
	}

	func padData(data: [Byte]) -> [Block] {
		var blocks = data.splitInSubArrays(into: block_size)
		let to_pad =
			blocks.last!.count % block_size == 0
			? 0 : block_size - (blocks.last!.count % block_size)
		// because ansiX923 always adds between 1 to 8 bytes
		if padding != PaddingMode.ansiX923 && to_pad == 0 {
			return blocks
		}
		switch padding {
			case .zeros:
				blocks[blocks.count - 1].append(contentsOf: Array(repeating: 0, count: to_pad))
			case .pkcs7:
				blocks[blocks.count - 1].append(
					contentsOf: Array(repeating: UInt8(to_pad), count: to_pad))
			case .iso10126:
				blocks[blocks.count - 1].append(
					contentsOf: (1..<to_pad).map({ _ in UInt8.random(in: 0...255) }))
				blocks[blocks.count - 1].append(UInt8(to_pad))
			case .ansiX923:
				let to_pad = to_pad == 0 ? 8 : to_pad
				if to_pad == 8 {
					blocks.append([])
				}
				blocks[blocks.count - 1].append(
					contentsOf: (1..<to_pad).map({ _ in UInt8.random(in: 0...255) }))
				blocks[blocks.count - 1].append(UInt8(to_pad))
		}
		return blocks
	}

	func unpadData(data: inout [Byte]) throws {
		switch self.padding {
			case .zeros:
				for i in (1...block_size) {
					if data[data.count - i] != 0 {
						data.removeLast(i - 1)
						break
					}
				}
			case .pkcs7:
				let n = data[data.count - 1]
				guard n < block_size && n < data.count else {
					return
				}

				let slice = data[data.count - Int(n)..<data.count]
				if slice.map({ $0 == n }).reduce(true, { x, y in x && y }) {
					data.removeLast(Int(n))
				}
			case .iso10126:
				let n = data[data.count - 1]
				guard n < block_size && n < data.count else {
					return
				}
				data.removeLast(Int(n))
			case .ansiX923:
				let n = data[data.count - 1]
				guard n <= block_size && n >= 1 && n < data.count else {
					throw EncryptionError.invalidPadding
				}
				data.removeLast(Int(n))
		}

	}

	public func encrypt(data: [Byte]) async throws -> [Byte] {
		if data.isEmpty {
			return []
		}
		let padded = padData(data: data)
		// let key = self.key
		let res: [Byte]
		let encryptor = self.encryptor
		switch mode {
			case .ecb:
				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = []
				for block in padded {
					tasks.append(
						Task {
							let new_block = try encryptor.encrypt(data: block)
							return new_block
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				res = arr
			case .cbc:
				var blocks = [self.iv ?? Array(repeating: 0, count: block_size)]
				for block in padded {
					let new_block = try self.encryptor.encrypt(data: block ^ blocks.last!)
					blocks.append(new_block)
				}
				res = blocks[1...].reduce(
					[],
					{ partial, block in
						return partial + block
					})
			case .pcbc:
				var to_xor = self.iv ?? Array(repeating: 0, count: block_size)
				var blocks: [Block] = []
				for block in padded {
					let new_block = try self.encryptor.encrypt(data: block ^ to_xor)
					blocks.append(new_block)
					to_xor ^= to_xor
					to_xor ^= block
					to_xor ^= blocks[blocks.count - 1]
				}
				res = blocks.reduce(
					[],
					{ partial, block in
						return partial + block
					})
			case .cfb:
				let iv = self.iv ?? Array(repeating: 0, count: block_size)
				var blocks: [Block] = [iv]
				for block in padded {
					blocks.lastMut = try self.encryptor.encrypt(data: blocks.last!)
					// SymmetricEncryptor.encryptBlock(block: &blocks.lastMut, key: key)
					blocks.lastMut ^= block
					blocks.append(blocks.lastMut)
				}
				res = blocks[0..<blocks.count - 1].reduce(
					[],
					{ partial, block in
						return partial + block
					})
			case .ofb:
				var prev = self.iv ?? Array(repeating: 0, count: block_size)
				var blocks: [Block] = []
				for block in padded {
					prev = try self.encryptor.encrypt(data: prev)
					// SymmetricEncryptor.encryptBlock(block: &prev, key: key)
					blocks.append(block ^ prev)
				}
				res = blocks.reduce(
					[],
					{ partial, block in
						return partial + block
					})
			case .ctr:
				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = []
				let iv = self.iv ?? Array(repeating: 0, count: block_size)
				for (i, block) in padded.enumerated() {
					tasks.append(
						Task {
							var new_block = iv
							new_block += UInt64(i)
							new_block = try encryptor.encrypt(data: new_block)
							// SymmetricEncryptor.encryptBlock(
							// 	block: &new_block, key: key)
							new_block ^= block
							return new_block
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				res = arr
			case .randomDelta:
				let iv = self.iv ?? Array.random(size: block_size)
				let delta_size = min(iv.count / 2, 8)
				let delta_start = iv.count - delta_size + 1
				let delta_bytes = Array(iv[delta_start...])
				let delta = delta_bytes.toUInt()

				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = try encryptor.encrypt(data: iv)
				for (i, block) in padded.enumerated() {
					tasks.append(
						Task {
							var new_block = iv
							new_block += delta * UInt64(i + 1)
							new_block ^= block
							return try encryptor.encrypt(data: new_block)
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				res = arr
		}
		return res
	}

	public func decrypt(data: [Byte]) async throws -> [Byte] {
		if data.isEmpty {
            return []
		}
		if data.count % block_size != 0 {
			throw EncryptionError.notFitting
		}

		let padded = data.splitInSubArrays(into: block_size)
		var res: [Byte]
		let encryptor = self.encryptor
		switch mode {
			case .ecb:
				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = []
				for block in padded {
					tasks.append(
						Task {
							let new_block = try encryptor.decrypt(data: block)
							return new_block
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				res = arr
			case .cbc:
				var blocks: [Block] = []
				var prev_block = self.iv ?? Array(repeating: 0, count: block_size)
				for block in padded {
					blocks.append(try encryptor.decrypt(data: block))
					// blocks.append(block)
					// SymmetricEncryptor.decryptBlock(block: &blocks[blocks.count - 1], key: key)
					blocks[blocks.count - 1] ^= prev_block
					prev_block = block
				}
				res = blocks.reduce(
					[],
					{ partial, block in
						return partial + block
					})
			case .pcbc:
				var to_xor = self.iv ?? Array(repeating: 0, count: block_size)
				var blocks: [Block] = []
				for block in padded {
					blocks.append(try encryptor.decrypt(data: block))
					// blocks.append(block)
					// SymmetricEncryptor.decryptBlock(block: &blocks.lastMut, key: key)
					blocks.lastMut ^= to_xor
					to_xor ^= to_xor
					to_xor ^= block
					to_xor ^= blocks.lastMut
				}
				res = blocks.reduce(
					[],
					{ partial, block in
						return partial + block
					})
			case .cfb:
				let iv = self.iv ?? Array(repeating: 0, count: block_size)
				var blocks: [Block] = [iv]
				for block in padded {
					blocks.lastMut = try encryptor.encrypt(data: blocks.last!)

					// SymmetricEncryptor.encryptBlock(block: &blocks.lastMut, key: key)
					blocks.lastMut ^= block
					blocks.append(block)
				}
				res = blocks[0..<blocks.count - 1].reduce(
					[],
					{ partial, block in
						return partial + block
					})
			case .ofb:
				var prev = self.iv ?? Array(repeating: 0, count: block_size)
				var blocks: [Block] = []
				for block in padded {
					prev = try encryptor.encrypt(data: prev)
					// SymmetricEncryptor.encryptBlock(block: &prev, key: key)
					blocks.append(block ^ prev)
				}
				res = blocks.reduce(
					[],
					{ partial, block in
						return partial + block
					})
			case .ctr:
				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = []
				let iv = self.iv ?? Array(repeating: 0, count: block_size)
				for (i, block) in padded.enumerated() {
					tasks.append(
						Task {
							var new_block = iv
							new_block += UInt64(i)
							new_block = try encryptor.encrypt(data: new_block)
							// SymmetricEncryptor.encryptBlock(
							// 	block: &new_block, key: key)
							new_block ^= block
							return new_block
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				res = arr

			case .randomDelta:
				let iv = try encryptor.decrypt(data: padded[0])
				let delta_size = min(iv.count / 2, 8)
				let delta_start = iv.count - delta_size + 1
				let delta_bytes = Array(iv[delta_start...])
				let delta = delta_bytes.toUInt()
				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = []
				for (i, block) in padded[1...].enumerated() {
					tasks.append(
						Task {
							let new_block = try encryptor.decrypt(data: block)
							var new_iv = iv
							new_iv += delta * UInt64(i + 1)
							return new_block ^ new_iv
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				res = arr
		}
		try unpadData(data: &res)
		return res
	}
}
