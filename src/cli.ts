import { Command } from "commander";
const program = new Command();

// import * as packageJson from "#package.json";

import { create } from "xmlbuilder2";

interface Input {
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
    };
  };
}

program
  .name("npm-audit-plus-plus")
  .description("A tool to capture the output of npm audit and convert it to xml")
  .version("1.0.6");

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

      // when all ok, create success XML and short circuit
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
            name: "NPM Audit Summary",
            errors: 0,
            failures: 0,
            tests: 1,
          })
          .ele("testcase", {
            name: `Critical: 0, High: 0, Moderate: 0, Low: 0, Info: 0, Dependencies: ${depCount}`,
          });

        const xml = empty.end({ prettyPrint: true });
        console.log(xml);
        process.exit(0);
      }

      // else, some vulnerabilities were found, create failure XML
      const testcase = [
        {
          "@name": `Summary: Critical: ${critCount}, High: ${highCount}, Moderate: ${modCount}, Low: ${lowCount}, Info: ${infoCount}, Dependencies: ${depCount}`,
        },
      ];

      for (const advisory in input.advisories) {
        testcase.push({
          "@name":
            input.advisories[advisory].severity +
            ":" +
            input.advisories[advisory].module_name +
            "@" +
            input.advisories[advisory].vulnerable_versions +
            ": " +
            input.advisories[advisory].title,
          failure: {
            "@message":
              input.advisories[advisory].title +
              " - " +
              input.advisories[advisory].findings[0].version +
              " - " +
              input.advisories[advisory].findings[0].paths[0],
            "@type": "error",
            "#text": input.advisories[advisory].overview,
          },
        } as any);
      }

      const obj = {
        testsuits: {
          testsuite: {
            "@name": "NPM Audit Summary",
            "@errors": 0,
            "@failures":
              critCount + highCount + modCount + lowCount + infoCount,
            "@tests": critCount + highCount + modCount + lowCount + infoCount,
            testcase,
          },
        },
      };

      const doc = create(obj);
      const xml = doc.end({ prettyPrint: true });
      console.log(xml);

      if (critCount > 0) {
        process.exit(1);
      } else {
        process.exit(0);
      }
    });
  });

program.parse(process.argv);
