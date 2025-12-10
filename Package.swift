// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "Cryptography",
	platforms: [.macOS(.v26)],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
		.library(
			name: "Des",
			targets: ["Des"]
		),
		.library(
			name: "Rsa",
			targets: ["Rsa"]
		),
		.executable(name: "Main", targets: ["Main"]),
		.executable(name: "DesCmd", targets: ["DesCmd"]),
	],
	dependencies: [
		.package(url: "https://github.com/attaswift/BigInt.git", from: "5.4.0")
	],
	targets: [
		// Targets are the basic building blocks of a package, defining a module or a test suite.
		// Targets can depend on other targets in this package and products from dependencies.
		.target(
			name: "Des"
		),
		.target(
			name: "Rsa",
			dependencies: [.product(name: "BigInt", package: "BigInt")]
		),
		.executableTarget(
			name: "Main",
			dependencies: ["Des", "Rsa"],
		),
		.executableTarget(
			name: "DesCmd",
			dependencies: ["Des"],
		),

		.testTarget(
			name: "DesTests",
			dependencies: ["Des"]
		),
		.testTarget(
			name: "RsaTests",
			dependencies: ["Rsa"]
		),
	]
)
