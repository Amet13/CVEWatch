# Start with Docker

<!-- description: Run unpatched from the ghcr.io image on a homelab server or NAS, on a schedule, with state kept in a mounted folder. -->

The image `ghcr.io/amet13/unpatched` holds the `unpatched` binary and nothing
else (a static build on a distroless base, running as a non-root user). It is
for a homelab server or a NAS that can run a scheduled container, when you do not
want GitHub Actions.

Tags: a full version (`0.1.0`), `0.1`, `0` and `latest`. Pin a version if you want
upgrades to be your decision. The image is built for `linux/amd64` and
`linux/arm64`.

## Run it

Make a folder with your `unpatched.yml` ([how to write it](start-github.md)) and
run the image with that folder mounted at `/work`:

```sh
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e UNPATCHED_CACHE_DIR=/work/.cache \
  -v "$PWD:/work" \
  ghcr.io/amet13/unpatched
```

With no arguments the image runs `unpatched check --notify`. Why each option:

- `-v "$PWD:/work"`: the container's working directory is `/work`, where it
  looks for `unpatched.yml` and where it saves `.unpatched/state.json` (what was
  already sent, so you get no repeats).
- `--user "$(id -u):$(id -g)"`: files it writes in the folder belong to you.
- `UNPATCHED_CACHE_DIR=/work/.cache`: the database (a few tens of MB) is kept
  there between runs instead of being downloaded each time.

Add `.cache/` and `.unpatched/` to your `.gitignore` if the folder is a
repository. Keep it private: `unpatched.yml` lists your software.

Any other command works by adding it after the image name:

```sh
docker run --rm -v "$PWD:/work" ghcr.io/amet13/unpatched check --format markdown
docker run --rm -v "$PWD:/work" ghcr.io/amet13/unpatched explain CVE-2024-21762
docker run --rm -v "$PWD:/work" ghcr.io/amet13/unpatched search nextcloud
```

## Secrets

Chat channels need a secret in an environment variable (names are on
[Notifications](notifications.md)). Pass it through from your shell or an env
file, so it never appears in the command line:

```sh
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e UNPATCHED_CACHE_DIR=/work/.cache \
  -e UNPATCHED_TELEGRAM_TOKEN \
  -v "$PWD:/work" \
  ghcr.io/amet13/unpatched
```

or `--env-file unpatched.env` with the file outside any repository.

GitHub issues are not used outside GitHub Actions, unless you set `GITHUB_TOKEN`
and `GITHUB_REPOSITORY` and add `--github`. With plain Docker, the chat channels
and the report are what you have.

## On a schedule

Cron on the host:

```text
17 6 * * *  cd /srv/unpatched && docker run --rm --user 1000:1000 -e UNPATCHED_CACHE_DIR=/work/.cache --env-file /srv/unpatched.env -v /srv/unpatched:/work ghcr.io/amet13/unpatched --quiet check --notify
```

(Use your own user id.) A Compose service that you start with
`docker compose run --rm unpatched`:

```yaml
services:
  unpatched:
    image: ghcr.io/amet13/unpatched:0
    user: "1000:1000"
    environment:
      UNPATCHED_CACHE_DIR: /work/.cache
      UNPATCHED_TELEGRAM_TOKEN: ${UNPATCHED_TELEGRAM_TOKEN}
    volumes:
      - ./:/work
```

The exit code tells your scheduler how it went: see
[Exit codes](start-cli.md#exit-codes). A run that finds something to fix today
only exits with 1 when you add `--exit-code`.

## Use it from an MCP client

The MCP server runs in the image too, for agents that start servers with Docker.
See [With an agent](with-an-agent.md#docker).

## Build it yourself

```sh
docker build -f docker/Dockerfile -t unpatched .
```
