# npm-audit-plus-plus

![CI](https://github.com/rkristelijn/npm-audit-plus-plus/actions/workflows/ci.yml/badge.svg)
[![npm version](https://img.shields.io/npm/v/npm-audit-plus-plus)](https://www.npmjs.com/package/npm-audit-plus-plus)
[![npm downloads](https://img.shields.io/npm/dm/npm-audit-plus-plus)](https://www.npmjs.com/package/npm-audit-plus-plus)
![license](https://img.shields.io/badge/license-MIT-green)

A tool to convert `npm audit` JSON output to JUnit XML for CI/CD pipelines (GitLab, Jenkins, etc.).

```
npm audit --json | npx npm-audit-plus-plus > npm-audit-plus-plus.xml
npm audit --production --json | npx npm-audit-plus-plus > npm-audit-plus-plus.xml
npm audit --omit=dev --json | npx npm-audit-plus-plus > npm-audit-plus-plus.xml
```

The tool is similar to [`npm-audit-plus`](https://github.com/freedomofpress/npm-audit-plus) but splits `npm audit` execution to be able to run `npm audit` with custom arguments.

## node version <= 14

Instead of npx you could use `npm i -D npm-audit-plus-plus@latest -f` to force to run it. Command has a limitation in package.json that it needs Node>16. But it seems to run fine with Node 14. Add a script to package.json:

```json
{
  "scripts": {
    "ci:audit": "npm audit --json --production | npm-audit-plus-plus > npm-audit.junit.xml"
  }
}
```

## Developing
- `npm i` - to install dependencies
- `npm t` - to parse all json files in `test/fixtures`. See if the changes are still valid.

## Docs

- [JUnit XML format](https://www.ibm.com/docs/en/developer-for-zos/14.1?topic=formats-junit-xml-format)
- [Gitlab JUnit parser info](https://gitlab.com/gitlab-org/gitlab/-/issues/299086)

## Sponsor me

[Sponsor me](https://github.com/sponsors/rkristelijn/) if you appreciate my work.
