"""External executable adapters. No shell execution and no Python DNS resolver."""

import asyncio
import ipaddress
import json
import logging
import os
import signal
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path

from .normalization import ipv4_addresses, normalize_hostname

LOG = logging.getLogger(__name__)


class ToolError(RuntimeError):
    pass


def read_json(url: str, timeout: float, payload=None, max_bytes=32 * 1024 * 1024):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, headers={
        "User-Agent": "assetwatch/0.1", "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ToolError("JSON response exceeded size limit")
    return json.loads(body)


def read_text(url: str, timeout: float, max_bytes=1024 * 1024):
    request = urllib.request.Request(url, headers={"User-Agent": "assetwatch/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ToolError("Text response exceeded size limit")
    return body.decode("utf-8")


def json_lines(path: Path):
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except (ValueError, UnicodeError) as error:
                raise ToolError(f"Malformed JSON output at line {number}") from error
            if not isinstance(row, dict):
                raise ToolError(f"Expected JSON object at line {number}")
            yield row


def text_lines(path: Path):
    with path.open(encoding="utf-8") as stream:
        yield from stream


class ToolRunner:
    def __init__(self, config):
        self.config = config

    async def stop_process(self, process):
        # Kill the process group too: ShuffleDNS starts MassDNS children.
        def send(sig):
            try:
                if os.name == "posix":
                    os.killpg(process.pid, sig)
                else:
                    process.terminate() if sig == signal.SIGTERM else process.kill()
            except ProcessLookupError:
                pass

        send(signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), timeout=3)
        except TimeoutError:
            pass
        finally:
            send(signal.SIGKILL)
            await process.wait()

    @asynccontextmanager
    async def run(self, name: str, args: list[str], input_path: Path | None = None, *,
                  merge_stderr=False, env=None, context=""):
        command = [self.config["tools"][name], *args]
        with tempfile.TemporaryDirectory(prefix="assetwatch-tool-") as directory:
            output, errors = Path(directory) / "stdout", Path(directory) / "stderr"
            with output.open("wb") as stdout, errors.open("wb") as stderr:
                stdin = input_path.open("rb") if input_path else None
                try:
                    try:
                        process = await asyncio.create_subprocess_exec(
                            *command, stdin=stdin or asyncio.subprocess.DEVNULL,
                            stdout=stdout, stderr=stdout if merge_stderr else stderr,
                            env={**os.environ, **env} if env is not None else None,
                            start_new_session=os.name == "posix")
                    except OSError as error:
                        raise ToolError(f"{name}: cannot execute configured tool ({error.strerror})") from error
                    started = asyncio.get_running_loop().time()
                    LOG.info("tool=%s %s state=started pid=%s", name, context, process.pid)
                    waiter = asyncio.create_task(process.wait())
                    try:
                        async with asyncio.timeout(self.config["runtime"]["tool_timeout"]):
                            while True:
                                done, _ = await asyncio.wait(
                                    {waiter}, timeout=self.config["runtime"]["progress_interval"])
                                if done:
                                    await waiter
                                    break
                                LOG.info("tool=%s %s state=running elapsed_seconds=%.1f output_bytes=%s stderr_bytes=%s",
                                         name, context, asyncio.get_running_loop().time() - started,
                                         output.stat().st_size, errors.stat().st_size)
                    except (TimeoutError, asyncio.CancelledError) as error:
                        await self.stop_process(process)
                        if isinstance(error, asyncio.CancelledError):
                            raise
                        raise ToolError(f"{name}: timeout; process group terminated") from error
                    finally:
                        if not waiter.done():
                            waiter.cancel()
                        await asyncio.gather(waiter, return_exceptions=True)
                finally:
                    if stdin:
                        stdin.close()
            with errors.open("r", encoding="utf-8", errors="replace") as stream:
                error_text = stream.read(8192).strip()
            if error_text:
                LOG.warning("tool=%s exit_code=%s stderr=%r", name, process.returncode, error_text)
            if process.returncode:
                with output.open("r", encoding="utf-8", errors="replace") as stream:
                    LOG.error("tool=%s exit_code=%s stdout=%r", name, process.returncode, stream.read(1024))
                raise ToolError(f"{name}: exited with code {process.returncode}")
            LOG.info("tool=%s exit_code=0 output_bytes=%s", name, output.stat().st_size)
            yield output


class Tools:
    def __init__(self, config):
        self.config = config
        self.runner = ToolRunner(config)

    @asynccontextmanager
    async def passive(self, source: str, domain: str):
        if source == "crtsh":
            query = urllib.parse.urlencode({"q": "%." + domain, "output": "json"})
            # crt.sh exposes an HTTP JSON endpoint, not an official executable.
            try:
                records = await asyncio.to_thread(read_json, "https://crt.sh/?" + query,
                                                  self.config["runtime"]["request_timeout"])
            except (OSError, ValueError) as error:
                raise ToolError(f"crtsh: request failed ({type(error).__name__})") from error
            if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
                raise ToolError("crtsh: expected a JSON array of certificates")
            yield (name for row in records for name in str(row.get("name_value", "")).splitlines())
        else:
            env = None
            if source == "chaos":
                # Keep the key out of argv and out of the parent process environment.
                key = self.config["chaos"]["api_key"]
                if key:
                    env = {"PDCP_API_KEY": key, "CHAOS_KEY": key}
            args = ["-d", domain, "-silent", "-duc"]
            if source == "subfinder":
                args.append("-recursive")
            async with self.runner.run(source, args,
                                       env=env, context=f"domain={domain}") as path:
                yield text_lines(path)

    @asynccontextmanager
    async def certificates(self, cidrs: list[str]):
        with tempfile.TemporaryDirectory(prefix="assetwatch-tls-") as directory:
            inputs = Path(directory) / "cidrs.txt"
            inputs.write_text("\n".join(cidrs) + "\n", encoding="utf-8")
            args = ["-json", "-silent", "-san", "-cn", "-duc", "-c", str(self.config["runtime"]["threads"])]
            async with self.runner.run("tlsx", args, inputs) as path:
                networks = [ipaddress.ip_network(cidr) for cidr in cidrs]

                def names():
                    for row in json_lines(path):
                        try:
                            ip = ipaddress.ip_address(row.get("ip") or row.get("host"))
                        except (ValueError, TypeError):
                            continue
                        if not any(ip in network for network in networks):
                            continue
                        if row.get("subject_cn"):
                            yield row["subject_cn"]
                        alternatives = row.get("subject_an", [])
                        if not isinstance(alternatives, list):
                            raise ToolError("tlsx: invalid subject_an field")
                        yield from alternatives

                yield names()

    async def dns(self, hostnames: list[str]) -> dict[str, list[str]]:
        with tempfile.TemporaryDirectory(prefix="assetwatch-dns-") as directory:
            inputs = Path(directory) / "hosts.txt"
            inputs.write_text("\n".join(hostnames) + "\n", encoding="utf-8")
            args = ["-a", "-json", "-silent", "-duc", "-rcode", "noerror,nxdomain,servfail,refused",
                    "-t", str(self.config["runtime"]["threads"])]
            async with self.runner.run("dnsx", args, inputs) as path:
                results, requested = {}, set(hostnames)
                for row in json_lines(path):
                    host = normalize_hostname(row.get("host"))
                    if host not in requested:
                        raise ToolError("dnsx: result has an unexpected hostname")
                    status = str(row.get("status_code", "")).upper()
                    if status in {"SERVFAIL", "REFUSED", "FORMERR"}:
                        LOG.warning("tool=dnsx host=%s response=%s state_preserved=true", host, status)
                        continue
                    if status not in {"NOERROR", "NXDOMAIN"}:
                        raise ToolError("dnsx: result has a missing or unsupported status_code")
                    addresses = row.get("a", [])
                    if not isinstance(addresses, list):
                        raise ToolError("dnsx: invalid A record list")
                    results[host] = ipv4_addresses(addresses) if status == "NOERROR" else []
                # Missing responses are inconclusive (timeouts), never evidence of DNS loss.
                if requested - results.keys():
                    LOG.warning("tool=dnsx inconclusive=%s state_preserved=true", len(requested - results.keys()))
                return results

    async def http(self, hostnames: list[str]) -> dict[str, dict | None]:
        with tempfile.TemporaryDirectory(prefix="assetwatch-http-") as directory:
            inputs = Path(directory) / "hosts.txt"
            inputs.write_text("\n".join(hostnames) + "\n", encoding="utf-8")
            args = ["-json", "-silent", "-duc", "-sc", "-title", "-server", "-ip", "-probe", "-auto-referer",
                    "-t", str(self.config["runtime"]["threads"])]
            async with self.runner.run("httpx", args, inputs) as path:
                requested, results = set(hostnames), {}
                for row in json_lines(path):
                    raw_host = row.get("input") or row.get("url")
                    if not isinstance(raw_host, str):
                        raise ToolError("httpx: missing input hostname")
                    parsed = urllib.parse.urlsplit(raw_host if "://" in raw_host else "//" + raw_host)
                    host = normalize_hostname(parsed.hostname)
                    if host not in requested:
                        raise ToolError("httpx: result has an unexpected hostname")
                    status = row.get("status_code")
                    if row.get("failed") is True or row.get("probe_status") is False:
                        results.setdefault(host, None)
                    elif type(status) is int and 100 <= status <= 599:
                        url = row.get("url", "")
                        parsed_url = urllib.parse.urlsplit(url)
                        if parsed_url.scheme not in {"http", "https"} or normalize_hostname(parsed_url.hostname) != host:
                            raise ToolError("httpx: invalid result URL")
                        observation = {key: row[key] for key in
                                       ("status_code", "url", "title", "webserver", "content_type", "content_length", "host", "a")
                                       if key in row}
                        existing = results.get(host)
                        if not existing or (url.startswith("https://") and not existing["url"].startswith("https://")):
                            results[host] = observation
                    else:
                        raise ToolError("httpx: missing or invalid status_code")
                if requested - results.keys():
                    LOG.warning("tool=httpx inconclusive=%s state_preserved=true", len(requested - results.keys()))
                return results

    @asynccontextmanager
    async def shuffledns(self, domain: str, *, wordlist=None, candidates=None):
        settings = self.config["dns_bruteforce"]["shuffledns"]
        resolvers = self.config.path(settings["resolvers"])
        if not resolvers.is_file() or not resolvers.stat().st_size:
            raise ToolError(f"ShuffleDNS requires a nonempty resolver file: {resolvers}")
        threads = str(settings["threads"])
        args = ["-d", domain, "-r", str(resolvers), "-m", self.config["tools"]["massdns"],
                "-t", threads, "-wt", threads, "-silent", "-duc"]
        if wordlist is not None:
            args += ["-mode", "bruteforce", "-w", str(wordlist)]
        else:
            args += ["-mode", "resolve", "-l", str(candidates)]
        mode = "static" if wordlist is not None else "dynamic"
        async with self.runner.run("shuffledns", args, context=f"domain={domain} mode={mode}") as path:
            yield text_lines(path)

    @asynccontextmanager
    async def dnsgen(self, inputs: Path):
        async with self.runner.run("dnsgen", [str(inputs)]) as path:
            yield text_lines(path)
