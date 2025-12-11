import Darwin
import Symmetric
import Foundation

struct RunError: Error {
	let msg: String
	init(_ msg: String) {
		self.msg = msg
	}
}

enum EncryptionType {
	case Deal
	case Des
}

struct Params {
	var padding: PaddingMode?
	var mode: EncryptionMode?
	var type: EncryptionType?
	var key: Block?
	var iv: Block?
	var path_out: String?
	var path_in: String?
}

@main
struct Main {
	static func parseArgs(args: [String]) throws -> Params {
		var params = Params()

		for arg in args[2...] {
			if arg.hasPrefix("-p=") {
				let padding = arg.trimmingPrefix("-p=")
				params.padding =
					switch padding {
						case "zeros": PaddingMode.zeros
						case "ansiX923": PaddingMode.ansiX923
						case "pkcs7": PaddingMode.pkcs7
						case "iso10126": PaddingMode.iso10126
						default:
							throw RunError(
								"invalid padding: \(padding). Valid: \(PaddingMode.allCases)")
					}
			} else if arg.hasPrefix("-t=") {
				let type = arg.trimmingPrefix("-t=")
				params.type =
					switch type {
						case "deal": .Deal
						case "des": .Des
						default:
							throw RunError(
								"invalid type: \(type). Valid: [deal, des]")
					}
			} else if arg.hasPrefix("-iv=") {
				let iv = arg.trimmingPrefix("-iv=")
				params.iv = Array(iv.utf8)
			} else if arg.hasPrefix("-b=") {
				let mode = arg.trimmingPrefix("-b=")
				params.mode =
					switch mode {
						case "ecb": EncryptionMode.ecb
						case "cbc": EncryptionMode.cbc
						case "pcbc": EncryptionMode.pcbc
						case "cfb": EncryptionMode.cfb
						case "ofb": EncryptionMode.ofb
						case "ctr": EncryptionMode.ctr
						case "randomDelta": EncryptionMode.randomDelta
						default:
							throw RunError(
								"invalid mode: \(mode). Valid: \(EncryptionMode.allCases)")
					}
			} else if arg.starts(with: "-") {
				throw RunError(
					"invalid parameter: \(arg)")
			} else {
				if params.key == nil {
					params.key = Array(arg.utf8)
				} else if params.path_in == nil {
					params.path_in = arg
				} else if params.path_out == nil {
					params.path_out = arg
				} else {
					throw RunError("invalid argument. key and paths are already provided")
				}
			}

		}
		guard params.key != nil || params.path_in != nil || params.path_out != nil else {
			throw RunError("key, path to input and path to output must be provided")
		}
		params.padding = params.padding ?? PaddingMode.zeros
		params.mode = params.mode ?? EncryptionMode.randomDelta
		params.type = params.type ?? .Des

		return params
	}
	static func getEncryptor(params: Params) throws -> SymmetricEncryptor {
		return switch params.type! {
			case .Des:
				try SymmetricEncryptor(
					type: DesEncryptor.self,
					key: params.key!, mode: params.mode!, padding: params.padding!, iv: params.iv,
					args: [])
			case .Deal:
				try SymmetricEncryptor(
					type: DealEncryptor.self,
					key: params.key!, mode: params.mode!, padding: params.padding!, iv: params.iv,
					args: [])
		}
	}
	static func help(args: [String]) async throws {
		let path = args[0]
		let name = path.split(separator: "/").last!
		print("USAGE: \(name) <command>")
		print("COMMANDS:")
		print("\thelp:\tshows current text")
		print("\tencrypt\t<args> <in> <out>: encrypts file <in> and writes the result to <out>")
		print(
			"\tdecrypt\t<args> <key> <in> <out>: decrypts file <in> and writes the result to <out>")
		print("ARGS:")
		print("\t-p=<padding>:\tsets encryption padding")
		print("\t-iv=<iv>:\tsets iv")
		print("\t-b=<blockmode>:\tsets block mode")
		print("\t-t=<type>:\tsets encryption mode")
	}

	static func doStuff(params: Params, operation: ([Byte]) async throws -> [Byte])
		async throws
	{
		guard let input = FileHandle(forReadingAtPath: params.path_in!) else {
			throw RunError("failed to open path: '\(params.path_in!)'")
		}
		FileManager.default.createFile(atPath: params.path_out!, contents: nil)
		guard let output = FileHandle(forWritingAtPath: params.path_out!) else {
			throw RunError("failed to open path: '\(params.path_out!)'")
		}
		defer {
			input.closeFile()
			output.closeFile()
		}

		let data = try input.readToEnd()
		guard data != nil else {
			throw RunError("failed to read")
		}
		let encrypted = try await operation(Array(data!))
		try output.write(contentsOf: encrypted)

	}

	static func encrypt(args: [String]) async throws {
		let params = try parseArgs(args: args)
		let encryptor = try Self.getEncryptor(params: params)
		try await Self.doStuff(params: params, operation: encryptor.encrypt)
	}

	static func decrypt(args: [String]) async throws {
		let params = try parseArgs(args: args)
		let encryptor = try Self.getEncryptor(params: params)
		try await Self.doStuff(params: params, operation: encryptor.decrypt)
	}

	static func main() async throws {
		do {
			let commands = [
				"help": Self.help,
				"encrypt": Self.encrypt,
				"decrypt": Self.decrypt,
			]
			let args = CommandLine.arguments
			guard args.count >= 2 else {
				throw RunError("not enough arguments")
			}
			guard let handle = commands[args[1]] else {
				throw RunError("invalid command \(args[1])")
			}
			try await handle(args)
		} catch let e as RunError {
			print("ERROR: \(e.msg)")
			exit(-1)
		} catch let e as EncryptionError {
			switch e {
				case .iv: print("ERROR: iv must be the same length as key")
				case .keySize(_, let msg): print("ERROR: invalid key length: \(msg ?? "")")
				case .invalidPadding: print("ERROR: invalid padding")
				default: print("ERROR: fatal")
			}
			exit(-1)
		}
	}
}
