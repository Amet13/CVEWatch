## Description

Please provide a clear and concise description of your changes.

## Type of Change

Please check the type of change your PR introduces:

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📝 Documentation update
- [ ] 🎨 Code style update (formatting, renaming)
- [ ] ♻️ Code refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] ✅ Test update
- [ ] 🔧 Build configuration change
- [ ] 🔒 Security fix

## Related Issues

Closes #(issue number)
Fixes #(issue number)
Related to #(issue number)

## Changes Made

Please provide a detailed list of changes:

- Change 1
- Change 2
- Change 3

## Motivation and Context

Why is this change required? What problem does it solve?

## How Has This Been Tested?

Please describe the tests that you ran to verify your changes:

- [ ] Unit tests
- [ ] Integration tests
- [ ] Manual testing

**Test Configuration**:

- OS:
- Go version:
- CVEWatch version:

## Test Commands

```bash
# Commands used to test
make test
make test-coverage
```

## Screenshots (if applicable)

Add screenshots to demonstrate the changes.

## Checklist

Please check all applicable items:

### Code Quality

- [ ] My code follows the project's code style guidelines
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] My changes generate no new warnings or errors
- [ ] I have run `make lint` and fixed all issues
- [ ] I have run `make security-scan` and addressed any findings

### Testing

- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] I have run `make test` and all tests pass
- [ ] I have run `make test-race` to check for race conditions

### Documentation

- [ ] I have updated the documentation accordingly
- [ ] I have updated the README.md if needed
- [ ] I have updated the config.yaml.example if needed
- [ ] I have added/updated code comments where necessary

### Dependencies

- [ ] My changes require a documentation update
- [ ] I have updated go.mod and go.sum if I added dependencies
- [ ] I have run `make deps-tidy`
- [ ] All dependencies are from trusted sources

### Commits

- [ ] My commits follow the Conventional Commits specification
- [ ] Each commit is atomic and has a clear purpose
- [ ] I have rebased my branch on the latest main

### Breaking Changes

- [ ] This PR introduces breaking changes (document below)
- [ ] I have updated the version number appropriately
- [ ] I have updated migration documentation

## Breaking Changes

If this PR introduces breaking changes, please describe:

1. What breaks?
2. Why was this change necessary?
3. How should users update their code/configuration?
4. Migration guide:

```
# Migration steps
```

## Performance Impact

If applicable, describe the performance impact:

- [ ] No performance impact
- [ ] Performance improvement (describe below)
- [ ] Potential performance degradation (describe below and justify)

**Benchmarks** (if applicable):

```
# Paste benchmark results
```

## Security Considerations

- [ ] This change has no security implications
- [ ] This change improves security (describe below)
- [ ] This change has security implications (describe below)

**Security Details**:

## Additional Notes

Any additional information that reviewers should know:

## Deployment Notes

Special deployment considerations:

- Configuration changes required:
- Migration steps required:
- Backward compatibility:

## Reviewer Notes

Specific areas to focus on during review:

1. Area 1
2. Area 2
3. Area 3

## Post-Merge Tasks

- [ ] Update documentation website
- [ ] Announce in discussions
- [ ] Update examples
- [ ] Create follow-up issues

---

## For Maintainers

### Review Checklist

- [ ] Code review completed
- [ ] Tests reviewed and passing
- [ ] Documentation adequate
- [ ] Security implications considered
- [ ] Performance impact acceptable
- [ ] Breaking changes documented
- [ ] Changelog updated (if needed)

### Merge Strategy

- [ ] Squash and merge
- [ ] Rebase and merge
- [ ] Create a merge commit
