#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var commander_1 = require("commander");
var program = new commander_1.Command();
var xmlbuilder2_1 = require("xmlbuilder2");
program
    .name("npm-audit-plus-plus")
    .description("A tool to capture the output of npm audit and convert it to xml")
    .version("1.0.13");
program
    .description("npm audit --json | npx npm-audit-plus-plus")
    .option("--debug", "display debug information")
    .action(function () {
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
        var input;
        try {
            input = JSON.parse(rawInput);
        }
        catch (e) {
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
                info: infoCount,
            });
        }
        // when all ok, create success XML and short circuit
        if (critCount === 0 &&
            highCount === 0 &&
            modCount === 0 &&
            lowCount === 0 &&
            infoCount === 0) {
            var empty = (0, xmlbuilder2_1.create)({ version: "1.0" })
                .ele("testsuits")
                .ele("testsuite", {
                name: "NPM Audit Summary",
                errors: 0,
                failures: 0,
                tests: 1,
            })
                .ele("testcase", {
                name: "Critical: 0, High: 0, Moderate: 0, Low: 0, Info: 0, Dependencies: ".concat(depCount),
            });
            var xml_1 = empty.end({ prettyPrint: true });
            console.log(xml_1);
            process.exit(0);
        }
        // else, some vulnerabilities were found, create failure XML
        var testcase = [
            {
                classname: "Summary",
                "@name": "Critical: ".concat(critCount, ", High: ").concat(highCount, ", Moderate: ").concat(modCount, ", Low: ").concat(lowCount, ", Info: ").concat(infoCount, ", Dependencies: ").concat(depCount),
            },
        ];
        for (var advisory in input.advisories) {
            var failure = input.advisories[advisory].severity === "critical"
                ? {
                    "@message": input.advisories[advisory].title +
                        " - " +
                        input.advisories[advisory].findings[0].version +
                        " - " +
                        input.advisories[advisory].findings[0].paths[0],
                    "@type": "error",
                    "#text": input.advisories[advisory].overview,
                }
                : null;
            testcase.push({
                "@name": input.advisories[advisory].title +
                    "\n" +
                    input.advisories[advisory].overview +
                    "\n" +
                    input.advisories[advisory].references,
                "@classname": input.advisories[advisory].module_name +
                    "@" +
                    input.advisories[advisory].vulnerable_versions +
                    " (" +
                    input.advisories[advisory].severity +
                    ")",
                failure: failure,
            });
        }
        var obj = {
            testsuites: {
                testsuite: {
                    "@name": "NPM Audit Summary",
                    "@errors": critCount,
                    "@failures": critCount,
                    "@tests": critCount + highCount + modCount + lowCount + infoCount,
                    testcase: testcase,
                },
            },
        };
        var doc = (0, xmlbuilder2_1.create)(obj);
        var xml = doc.end({ prettyPrint: true });
        console.log(xml);
        if (critCount > 0) {
            process.exit(1);
        }
        else {
            process.exit(0);
        }
    });
});
program.parse(process.argv);
