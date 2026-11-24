# FAQ

<!-- description: Answers to common questions: why not Dependabot, Trivy or OpenCVE, why a finding is unknown, why a product is unverified, public repositories, and schedule pauses. -->

## Why not Dependabot or Renovate?

They keep the dependencies of your code up to date. They do not know about a
FortiGate, a NAS or a Nextcloud server that you installed and did not write. Use
them for code and use unpatched for what you run.

## Why not Trivy, Grype or OSV-Scanner?

Those scan container images, file systems and lock files, and they are the right
tool for that. They find the packages themselves and list every known CVE in
them. unpatched does the opposite: you tell it what runs, at the level of a
product (FortiOS 7.2.5, Nextcloud 29.0.3), and it ranks what matters by
exploitation. The two fit together: scan your images with Trivy, and watch your
firewall, VPN and apps with unpatched. unpatched can also check a single package
you name with a `purl`, but it does not discover packages.

## Why not OpenCVE, Vulners or an NVD alert?

CVE feeds show every CVE for a vendor and leave the sorting to you. About 40% of
CVEs have a CVSS score of 7 or more, so a filter on CVSS is mostly noise.
unpatched compares the CVE's affected versions with the version you run, then
ranks by evidence of exploitation (CISA KEV, SSVC, public exploits, EPSS). The
result is rare, specific and says what to do. It also keeps no accounts and no
server for you to depend on.

## Why is a finding `unknown`?

Because the data cannot say, and unpatched does not guess. Read the rule on the
finding:

- `UNP-UNKNOWN-NO-RANGES`: no source has version data yet. New CVEs often wait days
  or weeks for NVD analysis. The finding goes away, or becomes `affected`, when
  data arrives. Read the advisory and check your version by hand.
- `UNP-UNKNOWN-VERSION`: your version, or a version in the data, cannot be read in
  the product's version scheme. Check the version in `unpatched.yml` (a build
  suffix, a typo, `latest`). If it is right, report it: the product may need a
  better scheme.
- `UNP-UNVERIFIED-PRODUCT`: the catalog's names for the product match nothing in the
  database, so an empty result would not mean you are safe.
- `UNP-STALE-DATA`: the database is old.

An `unknown` is only shown when it would matter if it were confirmed. `unknown`
is never turned into "not affected". See [Findings and rules](findings.md).

## Why does it say my product is not verified?

The catalog ties a product's names in NVD, CVE records and KEV together. A person
checks each entry against real data and records the date as `checked:`. "Not
verified" (rule `UNP-UNVERIFIED-PRODUCT`) means that, in the current database, the
entry's names matched no record at all. Either the product really has no known
vulnerabilities, or a name is wrong. unpatched cannot tell which, so it does not
say you are safe. Report it with the **Wrong verdict** or **Add a product**
template and the entry will be checked. See [Catalog](catalog.md).

## Why is my product not in the catalog?

The catalog is checked by hand, so it grows by request. See
[Ask for a product](catalog.md#ask-for-a-product). For a library or an operating
system package you can use a `purl` today.

## Why did it flag something that does not apply to me?

unpatched matches by version, and it does not know your configuration. A CVE may
need a feature that you have turned off. If you are sure, add an `ignore` entry
with a reason and an `until` date; it comes back when the date passes. See
[the config](config.md#ignore-entries). If the verdict is wrong for everyone,
please report it.

## Why did it not flag a CVE I read about?

Common reasons: the product is not in the catalog; NVD has no version data for it
yet (it may be `unknown` and not shown); your version is outside the affected range;
or the database is older than the news. Run `unpatched explain CVE-...` to see what the
data says, and `unpatched db info` for the age of the data.

## Can I use a public repository?

You can, but you should not. `unpatched.yml` lists your software and versions, and
the issues and the status issue name them. In a public repository anyone can read
that, which is a map for an attacker. Use a private repository. `unpatched init`
reminds you of this.

If you do use a public one, remember that GitHub pauses scheduled workflows there
(see the next question).

## Will the schedule stop?

GitHub disables scheduled workflows after 60 days with no repository activity,
**only in public repositories**. In a private repository the schedule keeps
running. unpatched does not commit to your repository to fake activity: it
needs only `issues: write`. If you run it from a public repository anyway, make a
commit now and then, or run the workflow by hand from the Actions tab when you get
the "workflow disabled" email from GitHub.

## Does it need an API key or an account?

No. Every data source works without one, and the database is public. The only
secrets are optional: tokens for chat channels, kept in GitHub secrets or
environment variables. See [Notifications](notifications.md).

## Does it cost anything?

No. The code is MIT licensed and the data is open. The Action runs on GitHub's
runners and uses a little of your Actions minutes (a private repository on the
free plan has 2,000 a month).

## Does it fix or update anything?

No. It tells you what to do and with which version. You do the upgrade, then
change the version in `unpatched.yml`, and the next run closes the issue.

## Can it find what I run by itself?

Not yet. You write the list, or an agent helps you build it from a compose file or
a pasted list (the `inventory-from-notes` skill). Reading local package lists
(dpkg, apk, rpm, brew, winget, docker) may come later.

## How do I report a wrong verdict?

Open an issue with the **Wrong verdict** template:
<https://github.com/Amet13/unpatched/issues/new/choose>. Give the product, the
version, the CVE, what you expected and what you got, and the output of
`unpatched explain <CVE>`. Each report becomes a failing test case first, then a
fix. See [How accurate is it](accuracy.md).

## Where does the data come from, and is it current?

See [Data](data.md). The database is built daily; `unpatched db info` shows its
age.
