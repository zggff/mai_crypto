public enum BitOrder {
	case forward
	case backward
}

public enum FirstBitIndex {
	case zero
	case one
}

// only direct p-block rule is a map where
public func transpose(data: [UInt8], rule: [Int], order: BitOrder, firstBit: FirstBitIndex) -> [UInt8]? {
	let shift =
		switch firstBit {
		case .one: 1
		default: 0
		}

	if data.count * 8 % rule.count != 0 {
		return nil
	}
	var b = Array.init(repeating: UInt8(0), count: data.count)
	for i in 0..<data.count * 8 {
		let block = i / rule.count
		let blockShift = rule[i % rule.count] - shift
		let pos =
			switch order {
			case .forward: block * rule.count + blockShift
			case .backward: (block + 1) * rule.count - blockShift - 1
			}
		b.setBit(pos, data.bit(i))
	}
	return b
}
