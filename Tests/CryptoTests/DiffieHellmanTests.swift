import BigInt
import Testing

@testable import Crypto

@Suite("Diffie")
struct DiffieHellmanTests {
	@Test("Test sha256")
	func shaTest() {
		let msg = Array("hello sha256".utf8)
		let hash = SHA256.hash(msg)
		let hashHex = hash.toHexString()
		#expect("433855b7d2b96c23a6f60e70c655eb4305e8806b682a9596a200642f947259b1" == hashHex)

	}

	@Test("Test param generation")
	func diffieParamTest() async throws {
		let params = DiffieHellman.generateParameters(bitLength: 32)!

		let private1 = BigInt(6)
		let public1 = params.generatePublicKey(privateKey: private1)

		let private2 = BigInt(15)
		let public2 = params.generatePublicKey(privateKey: private2)

		let shared1 = DiffieHellman.computeSharedSecret(
			privateKey: private1,
			otherPublicKey: public2,
			p: params.p
		)
		let shared2 = DiffieHellman.computeSharedSecret(
			privateKey: private2,
			otherPublicKey: public1,
			p: params.p
		)

		#expect(shared1 == shared2)
        let symmetricKey1 = try DiffieHellman.deriveSymmetricKey(
			sharedSecret: shared1,
			keySize: 16
		)
        let symmetricKey2 = try DiffieHellman.deriveSymmetricKey(
			sharedSecret: shared2,
			keySize: 16
		)
        #expect(symmetricKey1 == symmetricKey2)


	}
	@Test("Test diffie with deal")
	func diffieTest() async throws {
		let params = DiffieHellman.Parameters(
			p: BigInt("23"),
			g: BigInt("5"),
			bitLength: 32
		)

		let private1 = BigInt(6)
		let public1 = RsaMath.modPow(params.g, private1, params.p)

		let private2 = BigInt(15)
		let public2 = RsaMath.modPow(params.g, private2, params.p)

		let shared1 = DiffieHellman.computeSharedSecret(
			privateKey: private1,
			otherPublicKey: public2,
			p: params.p
		)

		let shared2 = DiffieHellman.computeSharedSecret(
			privateKey: private2,
			otherPublicKey: public1,
			p: params.p
		)

		#expect(shared1 == shared2)

		let symmetricKey = try DiffieHellman.deriveSymmetricKey(
			sharedSecret: shared1,
			keySize: 16
		)
		let encryptor = try await BlockEncryptor(
			encryptor: try Feistel(expander: DealExpander(), transposer: DealTransposer()),
			key: symmetricKey,
			mode: .ecb,
			padding: .pkcs7,
			iv: nil,
			args: []
		)

		let testMessage = "Test DH integration"
		let messageBytes = Array(testMessage.utf8)

		let encrypted = try await encryptor.encrypt(data: messageBytes)
		let decrypted = try await encryptor.decrypt(data: encrypted)
		let decryptedMessage = String(bytes: decrypted, encoding: .utf8)

		#expect(
			decryptedMessage == testMessage)
	}
}
