enum BitOrder {
	case forward
	case backward
}

enum FirstBitIndex {
	case zero
	case one
}

extension UInt8 {
	func bitRepr() -> String {
		var res = "0b"
		for i in (0...7).reversed() {
			res += String(self[i] as UInt8)
		}
		return res
	}
	subscript(i: Int) -> Bool {
		get {
			return self & (1 << i) != 0
		}
		set(val) {
			switch val {
			case true: self |= (1 << i)
			case false: self &= ~(1 << i)
			}
		}
	}
	subscript(at: Int) -> UInt8 {
		get {
			return (self & (1 << at)) >> at
		}
		set(val) {
			switch val {
			case 0: self &= ~(1 << at)
			default: self |= (1 << at)
			}
		}
	}
}

extension [UInt8] {

	func bit(_ at: Int) -> Bool {
		return self[at / 8] & (1 << (at % 8)) != 0
	}

	mutating func setBit(_ at: Int, _ val: Bool) {
		switch val {
		case false: self[at / 8] &= ~(1 << (at % 8))
		case true: self[at / 8] |= (1 << (at % 8))
		}
	}

}

// only direct p-block rule is a map where
func transpose(data: [UInt8], rule: [Int], order: BitOrder, firstBit: FirstBitIndex) -> [UInt8]? {
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
