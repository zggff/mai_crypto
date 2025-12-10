import BigInt
import Testing

@testable import Rsa

@Suite("Test rsa")
struct TestRSA {
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
		#expect(
			StatelessMathService.jacobiSymbol(a: BigInt(100), n: BigInt(21))
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

    // RSAEncoder
    // RsaEncoder <- this is better
	@Test("Rsa", arguments: [RsaService.TestType.millerRabin])
	func testRsa(testType: RsaService.TestType) {
		var rng = SystemRandomNumberGenerator()
		let bitLength = 128
		let keyGen = RsaService.KeyGenerator(
			testType: .millerRabin, minProbability: 0.99, primeBitLength: bitLength)

		let kp = keyGen.generateKeyPair(randomGen: &rng)

		#expect(kp.n == kp.p * kp.q)

		// gcd(e, phi) == 1
		let phi = (kp.p - 1) * (kp.q - 1)
		#expect(StatelessMathService.gcd(kp.e, phi) == BigInt(1))

		if let inv = StatelessMathService.modInverse(kp.e, phi) {
			#expect((inv % phi + phi) % phi == (kp.d % phi + phi) % phi)
		} else {
			#expect(Bool(false))
		}

		let rsa = RsaService()
		rsa.setKeyPair(kp)

		let messageInt = BigInt(42)

		let cipher = rsa.encrypt(message: messageInt)
		#expect(cipher != messageInt)

		let decrypted = rsa.decrypt(cipher: cipher)
		#expect(decrypted == messageInt)
	}

	@Test("RSA strings")
	func testRsaString() {
		var rng = SystemRandomNumberGenerator()
		let bitLength = 128
		let keyGen = RsaService.KeyGenerator(
			testType: .millerRabin, minProbability: 0.99, primeBitLength: bitLength)
		let kp = keyGen.generateKeyPair(randomGen: &rng)

		let rsa = RsaService()
		rsa.setKeyPair(kp)

		let original = "this is a test message for rsa"
		let mInt = RsaService.messageToBigInt(original)

		let cipher = rsa.encrypt(message: mInt)
		let decrypted = rsa.decrypt(cipher: cipher)

		let decoded = RsaService.bigIntToMessage(decrypted)
		#expect(decoded! == original)
	}

	@Test("RSA protection")
	func testRSAProtection() {
		var rng = SystemRandomNumberGenerator()
		let bitLength = 256
		let keyGen = RsaService.KeyGenerator(
			testType: .millerRabin, minProbability: 0.99, primeBitLength: bitLength)
		let kp = keyGen.generateKeyPair(randomGen: &rng)

		let diff = abs(kp.p - kp.q)
		let fermatThreshold = BigInt(1) << max(1, (bitLength / 2) - 16)
		#expect(diff >= fermatThreshold, "abs(p - q) should be >= threshold")

		let nBitWidth = kp.n.bitWidth
		let dMin = BigInt(1) << max(1, nBitWidth / 4)
		#expect(kp.d > dMin, "d must be larger than threshold")
	}
}
