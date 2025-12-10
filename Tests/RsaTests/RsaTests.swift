import BigInt
import Testing

@testable import Rsa

@Suite("Test rsa")
struct TestRSA {
	@Test("Math service")
	func testMath() {
		let a = BigInt(56)
		let b = BigInt(98)
		let g = MathService.gcd(a, b)
		#expect(g == BigInt(14), "gcd(56,98) should be 14")

		let (g2, x, y) = MathService.extendedGCD(a, b)
		#expect(g2 == BigInt(14), "gcd should be 14")
		#expect(a * x + b * y == g2, "Bezout identity must hold: a*x + b*y == gcd")

		#expect(
			MathService.modInverse(BigInt(3), BigInt(11)) == BigInt(4))

		#expect(MathService.modPow(BigInt(3), BigInt(4), BigInt(5)) == BigInt(1))
		#expect(
			MathService.legendreSymbol(a: BigInt(2), p: BigInt(7))
				== 1)
		#expect(
			MathService.jacobiSymbol(a: BigInt(100), n: BigInt(21))
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

		#expect(kp.pub.n == kp.pri.p * kp.pri.q)

		// gcd(e, phi) == 1
		let phi = (kp.pri.p - 1) * (kp.pri.q - 1)
		#expect(MathService.gcd(kp.pub.e, phi) == BigInt(1))

		if let inv = MathService.modInverse(kp.pub.e, phi) {
			#expect((inv % phi + phi) % phi == (kp.pri.d % phi + phi) % phi)
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
		let bitLength = 256
		let keyGen = RsaService.KeyGenerator(
			testType: .millerRabin, minProbability: 0.99, primeBitLength: bitLength)
		let kp = keyGen.generateKeyPair()

		let diff = abs(kp.pri.p - kp.pri.q)
		let fermatThreshold = BigInt(1) << max(1, (bitLength / 2) - 16)
		#expect(diff >= fermatThreshold, "abs(p - q) should be >= threshold")

		let nBitWidth = kp.pub.n.bitWidth
		let dMin = BigInt(1) << max(1, nBitWidth / 4)
		#expect(kp.pri.d > dMin, "d must be larger than threshold")
	}

	@Test("Attack success")
	func rsaAttackSuccess() throws {
		let attack = RsaAttackService()

		let p = BigInt(997)
		let q = BigInt(1237)
		let n = p * q
		let phiN = (p - 1) * (q - 1)

		let d = BigInt(17)
		let e = MathService.modInverse(d, phiN)!

		let result = attack.attack(key: RsaService.PublicKey(n: n, e: e))

		#expect(result.d == d)
		#expect(result.phi == phiN)
		#expect(result.candidates.count > 0)
	}

	@Test("AttackFailWithGoodRsa")
	func rsaAttackFailure() throws {
		let attack = RsaAttackService()
		let keyGen = RsaService.KeyGenerator(
			testType: .millerRabin, minProbability: 0.99, primeBitLength: 128)
		let key = keyGen.generateKeyPair().pub
		let result = attack.attack(key: key)

		#expect(result.d == nil)
		#expect(result.phi == nil)
	}

}
