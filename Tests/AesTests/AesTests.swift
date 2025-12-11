import Testing

@testable import Aes

@Suite("Aes tests")
final class AesTests {
	@Test
	func testAddition() {
		#expect(GF256.add(0b1010_1010, 0b0101_0101) == 0b1111_1111)
		#expect(GF256.add(0b1111_0000, 0b1111_0000) == 0b0000_0000)
		#expect(GF256.add(0x57, 0x83) == 0xD4)

        for irr in GF256.allIrreducible() {
            #expect(GF256.factorPolynomial(irr).count == 1)
        }
	}
	@Test
    func testSbox() async throws {
        let sbox = try SBox(mod: 283)
        for val in await sbox.InvSBox {
            print("\(String(val, radix: 16))")
        }
    }
}
