import Testing

@testable import Cryptography

@Test func testBitOperations() async throws {
	var a: UInt8 = 0
	a[1] = true
	#expect(a == 2)
	a[7] = true
	#expect(a == 130)
}

@Test func testTransposition() async throws {
	let values: [UInt8] = [1, 2, 3, 4, 5, 6]
	var cipher = [7, 6, 5, 4, 3, 2, 1, 0]
	var res = Cryptography.transpose(
		data: values, rule: cipher, order: BitOrder.forward,
		firstBit: FirstBitIndex.zero)

	#expect(res != nil)
	#expect(res! == [128, 64, 192, 32, 160, 96])

	res = Cryptography.transpose(
		data: values, rule: cipher, order: BitOrder.backward,
		firstBit: FirstBitIndex.zero)

	#expect(res != nil)
	#expect(res! == [1, 2, 3, 4, 5, 6])

	cipher = [8, 7, 6, 5, 4, 3, 2, 1]

	res = Cryptography.transpose(
		data: values, rule: cipher, order: BitOrder.backward,
		firstBit: FirstBitIndex.one)

	#expect(res != nil)
	#expect(res! == [1, 2, 3, 4, 5, 6])
}
