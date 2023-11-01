#!/usr/bin/env node

import { Command } from "commander";
const program = new Command();
import { create } from "xmlbuilder2";

interface Input {
  auditReportVersion?: number; // for version 2 or the audit report
  vulnerabilities?: {
    name: string;
    severity: string;
    isDirect: boolean;
    via: string[];
    effect: string[];
    range: string;
    nodes: string[];
    fixAvailable: {
      name: string;
      version: string;
      isSemVerMajor: boolean;
    };
  };
  // below is version 1
  metadata: {
    vulnerabilities: {
      critical: number;
      high: number;
      moderate: number;
      low: number;
      info: number;
    };
    dependencies: number;
  };
  advisories: {
    [key: string]: {
      findings: {
        version: string;
        paths: string[];
      }[];
      id: number;
      created: string;
      updated: string;
      deleted: string;
      title: string;
      found_by: {
        link: string;
      };
      severity: string;
      module_name: string;
      vulnerable_versions: string;
      overview: string;
      references: string;
    };
  };
}

program
  .name("npm-audit-plus-plus")
  .description(
    "A tool to capture the output of npm audit and convert it to xml"
  )
  .version("1.0.14");

program
  .description("npm audit --json | npx npm-audit-plus-plus")
  .option("--debug", "display debug information")
  .action(() => {
    // read the options
    const options = program.opts();

    // read the input
    process.stdin.resume();
    let rawInput = "";
    process.stdin.on("data", (input) => {
      rawInput += input;
    });

    // when input ends, parse the file
    process.stdin.on("end", () => {
      let input: Input;
      try {
        input = JSON.parse(rawInput);
      } catch (e) {
        console.log("Error parsing JSON input");
        console.log(e);
        process.exit(1);
      }
      const critCount = input.metadata.vulnerabilities.critical;
      const highCount = input.metadata.vulnerabilities.high;
      const modCount = input.metadata.vulnerabilities.moderate;
      const lowCount = input.metadata.vulnerabilities.low;
      const infoCount = input.metadata.vulnerabilities.info;
      const depCount = input.metadata.dependencies;

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

      let xml = "";
      if (input.auditReportVersion === 2) {
        xml = v2(input);
      } else {
        xml = v1(input);
      }
      // when all ok, create success XML and short circuit
      console.log(xml);

      if (critCount > 0) {
        process.exit(1);
      } else {
        process.exit(0);
      }
    });
  });

program.parse(process.argv);

const v1 = (input: Input) => {
  const critCount = input.metadata.vulnerabilities.critical;
  const highCount = input.metadata.vulnerabilities.high;
  const modCount = input.metadata.vulnerabilities.moderate;
  const lowCount = input.metadata.vulnerabilities.low;
  const infoCount = input.metadata.vulnerabilities.info;
  const depCount = input.metadata.dependencies;

  if (
    critCount === 0 &&
    highCount === 0 &&
    modCount === 0 &&
    lowCount === 0 &&
    infoCount === 0
  ) {
    const empty = create({ version: "1.0" })
      .ele("testsuits")
      .ele("testsuite", {
        name: "NPM Audit Summary v1",
        errors: 0,
        failures: 0,
        tests: 1,
      })
      .ele("testcase", {
        name: `Critical: 0, High: 0, Moderate: 0, Low: 0, Info: 0, Dependencies: ${depCount}`,
      });

    const xml = empty.end({ prettyPrint: true });
    return xml;
  }

  // else, some vulnerabilities were found, create failure XML
  const testcase = [
    {
      "@classname": "Summary",
      "@name": `Critical: ${critCount}, High: ${highCount}, Moderate: ${modCount}, Low: ${lowCount}, Info: ${infoCount}, Dependencies: ${depCount}`,
    },
  ];

  for (const advisory in input.advisories) {
    const failure =
      input.advisories[advisory].severity === "critical"
        ? {
            "@message":
              input.advisories[advisory].title +
              " - " +
              input.advisories[advisory].findings[0].version +
              " - " +
              input.advisories[advisory].findings[0].paths[0],
            "@type": "error",
            "#text": input.advisories[advisory].overview,
          }
        : null;
    testcase.push({
      "@name":
        input.advisories[advisory].title +
        "\n" +
        input.advisories[advisory].overview +
        "\n" +
        input.advisories[advisory].references,
      "@classname":
        input.advisories[advisory].module_name +
        "@" +
        input.advisories[advisory].vulnerable_versions +
        " (" +
        input.advisories[advisory].severity +
        ")",
      failure,
    } as any);
  }

  const obj = {
    testsuites: {
      testsuite: {
        "@name": "NPM Audit Summary",
        "@errors": critCount,
        "@failures": critCount,
        "@tests": critCount + highCount + modCount + lowCount + infoCount,
        testcase,
      },
    },
  };

  const doc = create(obj);
  const xml = doc.end({ prettyPrint: true });
  return xml;
};

const v2 = (input: Input) => {
  const critCount = input.metadata.vulnerabilities.critical;
  const highCount = input.metadata.vulnerabilities.high;
  const modCount = input.metadata.vulnerabilities.moderate;
  const lowCount = input.metadata.vulnerabilities.low;
  const infoCount = input.metadata.vulnerabilities.info;
  const depCount = input.metadata.dependencies;
  const empty = create({ version: "1.0" })
    .ele("testsuits")
    .ele("testsuite", {
      name: "NPM Audit Summary v2 (work in progress)",
      errors: 0,
      failures: 0,
      tests: 1,
    })
    .ele("testcase", {
      name: `Critical: 0, High: 0, Moderate: 0, Low: 0, Info: 0, Dependencies: ${depCount}`,
    });
  return empty.end({ prettyPrint: true });
};
