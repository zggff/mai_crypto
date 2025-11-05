public func permute(data: [Byte], rule: [Int], order: BitOrder, firstBit: FirstBitIndex)
	-> [Byte]?
{
	let shift =
		switch firstBit {
			case .one: 1
			default: 0
		}
	var res = Array.init(repeating: UInt8(0), count: (rule.count - 1) / 8 + 1)
	for (i, pos) in rule.enumerated() {
		guard pos - shift >= 0 && pos - shift <= data.count * 8 else {
			print("exiting on \(pos) with rule: \(rule)")
			return nil
		}
		let pos =
			switch order {
				case .forward: (pos - shift)
				case .backward: res.count * 8 - (pos - shift) - 1
			}
		res.setBit(i, data.bit(pos))
	}
	return res
}
