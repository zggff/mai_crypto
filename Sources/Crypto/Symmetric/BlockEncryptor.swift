import Darwin
import Foundation

public class BlockEncryptor {
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

	let block_size: Int
	let mode: EncryptionMode
	let padding: PaddingMode
	let iv: [Byte]?
	let args: [EncryptionModeArg]
	let encryptor: any Encryptor

	public init(
		encryptor: Encryptor, key: [Byte], mode: EncryptionMode, padding: PaddingMode, iv: [Byte]?,
		args: [EncryptionModeArg]
	) async throws {
		self.encryptor = encryptor
		try await self.encryptor.setKey(key: key)
		self.mode = mode
		self.padding = padding
		self.iv = iv
		self.args = args
		if let key_sizes = await encryptor.keySizes() {
			if !key_sizes.contains(key.count) {
				throw EncryptionError.keySize(key.count, "key size must be one of \(key_sizes)")
			}
		}
		self.block_size = await self.encryptor.blockSize() ?? key.count
		if let iv = iv {
			if iv.count != self.block_size {
				throw EncryptionError.iv
			}
		}
		if padding == PaddingMode.ansiX923 && block_size > 8 {
			throw EncryptionError.blockSize(key.count, "ansiX923 block must be <= 8 bytes")
		}

	}

	func padData(data: [Byte]) -> [Block] {
		var blocks = data.chunked(into: block_size)
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

	public func encrypt(in from: String, out to: String) async throws {
		guard let input = FileHandle(forReadingAtPath: from) else {
			throw EncryptionError.fileOpen("failed to open path: '\(from)'")
		}
		FileManager.default.createFile(atPath: to, contents: nil)
		guard let output = FileHandle(forWritingAtPath: to) else {
			throw EncryptionError.fileOpen("failed to open path: '\(to)'")
		}
		defer {
			input.closeFile()
			output.closeFile()
		}

		let to_read = block_size * 1024 * 1024
		// let to_read = block_size

		var offset = 0
		var prevBlock: Block?
		while true {
			let data = try input.read(upToCount: to_read)
			guard let data = data else {
				break
			}
			let padded = padData(data: Array(data))
			let blocks: [Byte]
			(blocks, prevBlock, offset) = try await encryptBlocks(
				padded: padded, prevBlock: prevBlock, offset: offset)
			try output.write(contentsOf: blocks)
		}
	}

	public func decrypt(in from: String, out to: String) async throws {
		guard let input = FileHandle(forReadingAtPath: from) else {
			throw EncryptionError.fileOpen("failed to open path: '\(from)'")
		}
		FileManager.default.createFile(atPath: to, contents: nil)
		guard let output = FileHandle(forWritingAtPath: to) else {
			throw EncryptionError.fileOpen("failed to open path: '\(to)'")
		}
		defer {
			input.closeFile()
			output.closeFile()
		}

		let to_read = block_size * 1024 * 1024
		// let to_read = block_size

		var offset = 0
		var prevBlock: Block?
		while true {
			let data = try input.read(upToCount: to_read)
			guard let data = data else {
				break
			}
			if data.count % block_size != 0 {
				throw EncryptionError.notFitting
			}
			let padded = Array(data).chunked(into: block_size)
			var blocks: [Byte]
			(blocks, prevBlock, offset) = try await decryptBlocks(
				padded: padded, prevBlock: prevBlock, offset: offset)
			try unpadData(data: &blocks)
			try output.write(contentsOf: blocks)
		}
	}

	public func encrypt(data: [Byte]) async throws
		-> [Byte]
	{
		if data.isEmpty {
			return []
		}
		let padded = padData(data: data)
		let (res, _, _) = try await encryptBlocks(padded: padded)
		return res
	}

	public func decrypt(data: [Byte]) async throws
		-> [Byte]
	{
		if data.isEmpty {
			return []
		}
		if data.count % block_size != 0 {
			throw EncryptionError.notFitting
		}

		let padded = data.chunked(into: block_size)
		var (res, _, _) = try await decryptBlocks(padded: padded)
		try unpadData(data: &res)

		return res
	}

	public func encryptBlocks(padded: [Block], prevBlock: [Byte]? = nil, offset: Int = 0)
		async throws
		-> ([Byte], Block?, Int)
	{
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
							let new_block = try await encryptor.encrypt(data: block)
							return new_block
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				return (arr, nil, 0)
			case .cbc:
				var blocks = [prevBlock ?? self.iv ?? Array(repeating: 0, count: block_size)]
				for block in padded {
					let new_block = try await self.encryptor.encrypt(data: block ^ blocks.last!)
					blocks.append(new_block)
				}
				res = blocks[1...].reduce(
					[],
					{ partial, block in
						return partial + block
					})
				return (res, blocks.last, 0)

			case .pcbc:
				var to_xor = prevBlock ?? self.iv ?? Array(repeating: 0, count: block_size)
				var blocks: [Block] = []
				for block in padded {
					let new_block = try await self.encryptor.encrypt(data: block ^ to_xor)
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
				return (res, to_xor, 0)
			case .cfb:
				let iv = prevBlock ?? self.iv ?? Array(repeating: 0, count: block_size)
				var blocks: [Block] = [iv]
				for block in padded {
					blocks.lastMut = try await self.encryptor.encrypt(data: blocks.last!)
					// SymmetricEncryptor.encryptBlock(block: &blocks.lastMut, key: key)
					blocks.lastMut ^= block
					blocks.append(blocks.lastMut)
				}
				res = blocks[0..<blocks.count - 1].reduce(
					[],
					{ partial, block in
						return partial + block
					})
				return (res, blocks.last, 0)

			case .ofb:
				var prev = prevBlock ?? self.iv ?? Array(repeating: 0, count: block_size)
				var blocks: [Block] = []
				for block in padded {
					prev = try await self.encryptor.encrypt(data: prev)
					// SymmetricEncryptor.encryptBlock(block: &prev, key: key)
					blocks.append(block ^ prev)
				}
				let res = blocks.reduce(
					[],
					{ partial, block in
						return partial + block
					})
				return (res, blocks.last, 0)
			case .ctr:
				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = []
				let iv = self.iv ?? Array(repeating: 0, count: block_size)
				for (i, block) in padded.enumerated() {
					tasks.append(
						Task {
							var new_block = iv
							new_block += UInt64(i + offset)
							new_block = try await encryptor.encrypt(data: new_block)
							// SymmetricEncryptor.encryptBlock(
							// 	block: &new_block, key: key)
							new_block ^= block
							return new_block
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				return (arr, nil, padded.count)
			case .randomDelta:
				let iv = self.iv ?? Array.random(size: block_size)
				let delta_size = min(iv.count / 2, 8)
				let delta_start = iv.count - delta_size + 1
				let delta_bytes = Array(iv[delta_start...])
				let delta = delta_bytes.toUInt()

				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = try await encryptor.encrypt(data: iv)
				for (i, block) in padded.enumerated() {
					tasks.append(
						Task {
							var new_block = iv
							new_block += delta * UInt64(i + 1 + offset)
							new_block ^= block
							return try await encryptor.encrypt(data: new_block)
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				return (arr, nil, padded.count)
		}
	}

	public func decryptBlocks(padded: [Block], prevBlock: [Byte]? = nil, offset: Int = 0)
		async throws
		-> ([Byte], Block?, Int)
	{
		var res: [Byte]
		let encryptor = self.encryptor
		switch mode {
			case .ecb:
				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = []
				for block in padded {
					tasks.append(
						Task {
							let new_block = try await encryptor.decrypt(data: block)
							return new_block
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				return (arr, nil, 0)
			case .cbc:
				var blocks: [Block] = []
				var prev_block = prevBlock ?? self.iv ?? Array(repeating: 0, count: block_size)
				for block in padded {
					await blocks.append(try encryptor.decrypt(data: block))
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
				return (res, blocks.last, 0)

			case .pcbc:
				var to_xor = prevBlock ?? self.iv ?? Array(repeating: 0, count: block_size)
				var blocks: [Block] = []
				for block in padded {
					await blocks.append(try encryptor.decrypt(data: block))
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
				return (res, to_xor, 0)

			case .cfb:
				let iv = prevBlock ?? self.iv ?? Array(repeating: 0, count: block_size)
				var blocks: [Block] = [iv]
				for block in padded {
					blocks.lastMut = try await encryptor.encrypt(data: blocks.last!)

					// SymmetricEncryptor.encryptBlock(block: &blocks.lastMut, key: key)
					blocks.lastMut ^= block
					blocks.append(block)
				}
				res = blocks[0..<blocks.count - 1].reduce(
					[],
					{ partial, block in
						return partial + block
					})
				return (res, blocks.last, 0)

			case .ofb:
				var prev = prevBlock ?? self.iv ?? Array(repeating: 0, count: block_size)
				var blocks: [Block] = []
				for block in padded {
					prev = try await encryptor.encrypt(data: prev)
					// SymmetricEncryptor.encryptBlock(block: &prev, key: key)
					blocks.append(block ^ prev)
				}
				res = blocks.reduce(
					[],
					{ partial, block in
						return partial + block
					})
				return (res, blocks.last, 0)
			case .ctr:
				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = []
				let iv = self.iv ?? Array(repeating: 0, count: block_size)
				for (i, block) in padded.enumerated() {
					tasks.append(
						Task {
							var new_block = iv
							new_block += UInt64(i + offset)
							new_block = try await encryptor.encrypt(data: new_block)
							// SymmetricEncryptor.encryptBlock(
							// 	block: &new_block, key: key)
							new_block ^= block
							return new_block
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				return (arr, nil, padded.count)

			case .randomDelta:
				let iv = try await encryptor.decrypt(data: padded[0])
				let delta_size = min(iv.count / 2, 8)
				let delta_start = iv.count - delta_size + 1
				let delta_bytes = Array(iv[delta_start...])
				let delta = delta_bytes.toUInt()
				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = []
				for (i, block) in padded[1...].enumerated() {
					tasks.append(
						Task {
							let new_block = try await encryptor.decrypt(data: block)
							var new_iv = iv
							new_iv += delta * UInt64(i + 1 + offset)
							return new_block ^ new_iv
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				return (arr, nil, padded.count)
		}
	}
}
