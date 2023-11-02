# NPM Audit Plus Plus

This is a tool to help report `npm audit` in xml format for e.g. CI/CD for gitlab.

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
