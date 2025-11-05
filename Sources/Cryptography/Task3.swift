public final class Feistel: EncryptTransposer {
	let expander: KeyExpander
	let transposer: EncryptTransposer
	public init(expander: KeyExpander, transposer: EncryptTransposer) {
		self.expander = expander
		self.transposer = transposer
	}
	public func transpose(data: Block, key: Block) -> Block! {
		guard data.count == key.count && data.count % 2 == 0 else {
			return nil
		}
		let middle = data.count / 2
		let keys = self.expander.expandKey(key: key)
		var left = Array(data[..<middle])
		var right = Array(data[middle...])
		for key in keys {
            var x = transposer.transpose(data: right, key: key)!
            x ^= left
            left = right
            right = x
		}
		return right + left
	}
}
