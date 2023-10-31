"use strict";

function _readOnlyError(name) { throw new TypeError("\"" + name + "\" is read-only"); }
var _require = require("commander"),
  Command = _require.Command;
var program = new Command();
var packageJson = require("../package.json");
var _require2 = require("xmlbuilder2"),
  create = _require2.create;
program.name(packageJson.name).description(packageJson.description).version(packageJson.version);
program.description("npm audit --json | npx npm-audit-plus-plus").option("--debug", "display debug information").action(function () {
  // read the options
  var options = program.opts();

  // read the input
  process.stdin.resume();
  var rawInput = "";
  process.stdin.on("data", function (input) {
    rawInput += input;
  });

  // when input ends, parse the file
  process.stdin.on("end", function () {
    var input = "";
    try {
      JSON.parse(rawInput), _readOnlyError("input");
    } catch (e) {
      console.log("Error parsing JSON input");
      console.log(e);
      process.exit(1);
    }
    var critCount = input.metadata.vulnerabilities.critical;
    var highCount = input.metadata.vulnerabilities.high;
    var modCount = input.metadata.vulnerabilities.moderate;
    var lowCount = input.metadata.vulnerabilities.low;
    var infoCount = input.metadata.vulnerabilities.info;
    var depCount = input.metadata.dependencies;
    if (options.debug) {
      console.log(input);
      console.log({
        dependencies: depCount,
        critical: critCount,
        high: highCount,
        moderate: modCount,
        low: lowCount,
        info: infoCount
      });
    }

    // when all ok, create success XML and short circuit
    if (critCount === 0 && highCount === 0 && modCount === 0 && lowCount === 0 && infoCount === 0) {
      var empty = create({
        version: "1.0"
      }).ele("testsuits").ele("testsuite", {
        name: "NPM Audit Summary",
        errors: 0,
        failures: 0,
        tests: 1
      }).ele("testcase", {
        name: "Critical: 0, High: 0, Moderate: 0, Low: 0, Info: 0, Dependencies: ".concat(depCount)
      });
      var _xml = empty.end({
        prettyPrint: true
      });
      console.log(_xml);
      process.exit(0);
    }

    // else, some vulnerabilities were found, create failure XML
    var testcase = [{
      "@name": "Summary: Critical: ".concat(critCount, ", High: ").concat(highCount, ", Moderate: ").concat(modCount, ", Low: ").concat(lowCount, ", Info: ").concat(infoCount, ", Dependencies: ").concat(depCount)
    }];
    for (var advisory in input.advisories) {
      testcase.push({
        "@name": input.advisories[advisory].severity + ":" + input.advisories[advisory].module_name + "@" + input.advisories[advisory].vulnerable_versions + ": " + input.advisories[advisory].title,
        failure: {
          "@message": input.advisories[advisory].title + " - " + input.advisories[advisory].findings[0].version + " - " + input.advisories[advisory].findings[0].paths[0],
          "@type": "error",
          "#text": input.advisories[advisory].overview
        }
      });
    }
    var obj = {
      testsuits: {
        testsuite: {
          "@name": "NPM Audit Summary",
          "@errors": 0,
          "@failures": critCount + highCount + modCount + lowCount + infoCount,
          "@tests": critCount + highCount + modCount + lowCount + infoCount,
          testcase: testcase
        }
      }
    };
    var doc = create(obj);
    var xml = doc.end({
      prettyPrint: true
    });
    console.log(xml);
    if (critCount > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  });
});
program.parse(process.argv);
