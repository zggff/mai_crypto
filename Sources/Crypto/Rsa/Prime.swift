import BigInt
import Foundation

protocol PrimeTest {
	func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool
}

class AbstractPrimeTest: PrimeTest {
	let math = RsaMath.self

	let minProbability: Double

	init(minProbability: Double) {
		precondition(minProbability >= 0.5 && minProbability < 1.0)
		self.minProbability = minProbability
	}

	func isProbablyPrime(_ n: BigInt, randomBitGenerator: (Int) -> BigInt) -> Bool {
		if n < 2 { return false }
		if n == 2 || n == 3 { return true }
		if n % 2 == 0 { return false }
		let errorPerIteration = self.errorProbabilityPerIteration()
		let requiredIterations = iterationsNeededToReachProbability(
			minProb: minProbability, perIterError: errorPerIteration)
		for _ in 0..<requiredIterations {
			let a = randomInRange(2, n - 2, randomBitGenerator: randomBitGenerator)
			if !singleIteration(n: n, rand: { a }) { return false }
		}
		return true
	}

	func errorProbabilityPerIteration() -> Double {
		return 0.5
	}

	func iterationsNeededToReachProbability(minProb: Double, perIterError: Double) -> Int {
		if perIterError <= 0 { return 1 }
		let numerator = log(1 - minProb)
		let denom = log(perIterError)
		let k = Int(ceil(numerator / denom))
		return max(1, k)
	}

	func randomInRange(_ lo: BigInt, _ hi: BigInt, randomBitGenerator: (Int) -> BigInt) -> BigInt {
		precondition(lo <= hi)
		let range = hi - lo + 1
		let bitWidth = hi.bitWidth
		var r: BigInt
		repeat {
			r = randomBitGenerator(bitWidth) % range
		} while r < 0
		return lo + r
	}

	func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool {
		fatalError("override")
	}
}

class FermatTest: AbstractPrimeTest {
	override func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool {
		let a = rand()
		let res = RsaMath.modPow(a, n - 1, n)
		return res == 1
	}
	override func errorProbabilityPerIteration() -> Double { return 0.5 }
}

class SolovayStrassenTest: AbstractPrimeTest {
	override func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool {
		let a = rand()
		let x = RsaMath.modPow(a, (n - 1) / 2, n)
		let j = RsaMath.jacobiSymbol(a: a, n: n)
		var jMod = BigInt(0)
		if j == -1 { jMod = n - 1 } else if j == 0 { jMod = 0 } else { jMod = 1 }
		return x == jMod
	}
	override func errorProbabilityPerIteration() -> Double { return 0.5 }
}

class MillerRabinTest: AbstractPrimeTest {
	override func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool {
		let a = rand()
		var d = n - 1
		var s = 0
		while d % 2 == 0 {
			d >>= 1
			s += 1
		}
		var x = RsaMath.modPow(a, d, n)
		if x == 1 || x == n - 1 { return true }
		for _ in 1..<s {
			x = (x * x) % n
			if x == n - 1 { return true }
		}
		return false
	}
	override func errorProbabilityPerIteration() -> Double { return 0.25 }
}
