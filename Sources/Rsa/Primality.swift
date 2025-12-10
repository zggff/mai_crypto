import Foundation
import BigInt

protocol ProbabilisticPrimeTest {
    func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool
}

class AbstractProbabilisticTest: ProbabilisticPrimeTest {
    let math = StatelessMathService.self

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
        let requiredIterations = iterationsNeededToReachProbability(minProb: minProbability, perIterError: errorPerIteration)
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

// -- Fermat test
class FermatTest: AbstractProbabilisticTest {
    override func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool {
        let a = rand()
        let res = StatelessMathService.modPow(a, n - 1, n)
        return res == 1
    }
    override func errorProbabilityPerIteration() -> Double { return 0.5 } // worst-case for Fermat (Carmichael numbers aside)
}

// -- Solovay-Strassen test
class SolovayStrassenTest: AbstractProbabilisticTest {
    override func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool {
        let a = rand()
        let x = StatelessMathService.modPow(a, (n - 1) / 2, n)
        let j = StatelessMathService.jacobiSymbol(a: a, n: n)
        var jMod = BigInt(0)
        if j == -1 { jMod = n - 1 } else if j == 0 { jMod = 0 } else { jMod = 1 }
        return x == jMod
    }
    override func errorProbabilityPerIteration() -> Double { return 0.5 } // Solovay-Strassen gives error <= 1/2 per iteration
}

// -- Miller-Rabin
class MillerRabinTest: AbstractProbabilisticTest {
    override func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool {
        let a = rand()
        var d = n - 1
        var s = 0
        while d % 2 == 0 {
            d >>= 1
            s += 1
        }
        var x = StatelessMathService.modPow(a, d, n)
        if x == 1 || x == n - 1 { return true }
        for _ in 1..<s {
            x = (x * x) % n
            if x == n - 1 { return true }
        }
        return false
    }
    override func errorProbabilityPerIteration() -> Double { return 0.25 } // Miller-Rabin has error <= 1/4 per iteration
}
