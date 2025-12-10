import BigInt
import Testing

@testable import Rsa

@Suite("Test rsa")
struct TestRsa {
    @Test("Math service")
	func testMath() {
		let a = BigInt(56)
		let b = BigInt(98)
		let g = StatelessMathService.gcd(a, b)
		#expect(g == BigInt(14), "gcd(56,98) should be 14")

		let (g2, x, y) = StatelessMathService.extendedGCD(a, b)
		#expect(g2 == BigInt(14), "gcd should be 14")
		#expect(a * x + b * y == g2, "Bezout identity must hold: a*x + b*y == gcd")

		#expect(
			StatelessMathService.modInverse(BigInt(3), BigInt(11)) == BigInt(4))

		#expect(StatelessMathService.modPow(BigInt(3), BigInt(4), BigInt(5)) == BigInt(1))
		#expect(
			StatelessMathService.legendreSymbol(a: BigInt(2), p: BigInt(7))
				== 1)
        #expect(StatelessMathService.jacobiSymbol(a: BigInt(100), n: BigInt(21))
 == 1)

	}
    @Test("MillerRabinTest")
	func testMillerRabinOnPrimesAndComposites() {
		let mr = MillerRabinTest(minProbability: 0.99)
		let smallPrimes: [BigInt] = [2, 3, 5, 7, 11, 13, 17, 19]
		for p in smallPrimes {
			let ok = mr.isProbablyPrime(p, randomBitGenerator: { _ in BigInt(2) })
            #expect(ok, "\(p) should be reported prime")
		}
		let composites: [BigInt] = [4, 6, 8, 9, 15, 21, 25]
		for c in composites {
			let ok = mr.isProbablyPrime(c, randomBitGenerator: { _ in BigInt(2) })
            #expect(!ok, "\(c) should be composite")
		}
	}

    @Test("Fermat + SolovayStrassenTest")
	func testFermatAndSolovayStrassenSimple() {
		let fermat = FermatTest(minProbability: 0.99)
		let ss = SolovayStrassenTest(minProbability: 0.99)
        #expect(fermat.isProbablyPrime(17, randomBitGenerator: { _ in BigInt(3) }))
        #expect(ss.isProbablyPrime(17, randomBitGenerator: { _ in BigInt(3) }))
        #expect(!fermat.isProbablyPrime(15, randomBitGenerator: { _ in BigInt(3) }))
	    #expect(!ss.isProbablyPrime(15, randomBitGenerator: { _ in BigInt(3) }))
	}
}
