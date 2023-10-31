# NPM Audit Plus Plus

This is a tool to help report `npm audit` in xml format for e.g. CI/CD for gitlab.

```
npm audit > npm-audit-plus-plus > npm-audit-plus-plus.xml
```

The tool is similar to [`npm-audit-plus`](https://github.com/freedomofpress/npm-audit-plus) but splits `npm audit` execution to be able to run `npm audit` with custom arguments.

## Docs

- [JUnit XML format](https://www.ibm.com/docs/en/developer-for-zos/14.1?topic=formats-junit-xml-format)