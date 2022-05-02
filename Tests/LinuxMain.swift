import XCTest

import MultihashTests

var tests = [XCTestCaseEntry]()
tests += MultihashTests.allTests()
XCTMain(tests)
