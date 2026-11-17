# Installation Guide --- CAPE

## Requirements

-   **Operating systems:** Kali Linux (recommended), Ubuntu 22.04+, or
    Debian 12+
-   **Python:** 3.11 or newer
-   **Privileges:** Some network-scanning tools or scan modes may
    require elevated privileges. Run assessments only against systems
    you own or are explicitly authorized to test.
-   **Scope for the six bounded attack checks:** These modules accept
    `localhost` or a single literal private IP address. They do not
    accept public IP addresses, DNS hostnames, CIDR ranges, or URLs that
    point to a different host from the CAPE target.

## Step 1: Install system dependencies (Kali Linux)

Update the package index and install the external tools used by CAPE's
scanner plugins and bounded attack checks:

``` bash
sudo apt-get update
sudo apt-get install -y \
    nmap masscan nikto whatweb gobuster dirb sqlmap \
    wpscan enum4linux nbtscan snmp \
    zaproxy aircrack-ng kismet \
    python3-pip python3-venv \
    libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
```

Some tools are optional and are only needed for the corresponding scan
plugins or attack-module integrations. For example, SQLMap and Gobuster
are used when available by their respective bounded checks; SMB
enumeration requires Nmap. The Python-based HTTP header and
single-attempt HTTP Basic authentication checks use the Python standard
library.

Package names can vary by distribution and repository. If a package is
unavailable, consult that distribution's package documentation and
install only the tools required for the modules you intend to use.

## Step 2: Install the CAPE Python package

Open a terminal in the extracted or cloned project directory (the
directory containing `pyproject.toml`).

``` bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip
python -m pip install --upgrade pip

# Install CAPE and its declared dependencies
python -m pip install -e .
```

Alternatively, install the dependencies listed in `requirements.txt`:

``` bash
python -m pip install -r requirements.txt
```

The editable installation (`pip install -e .`) also installs the `cape`
command-line entry point declared by the project configuration.

To install development and test tools declared by the project:

``` bash
python -m pip install -e ".[dev]"
```

## Step 3: First-run setup

Check the installation and the availability of external tools:

``` bash
cape doctor
```

CAPE creates its configuration and workspace directories as needed. If
you want to create the standard directories manually:

``` bash
mkdir -p ~/.cape/workspaces ~/.cape/logs ~/.cape/db
```

If the project includes the example configuration file, copy it into the
CAPE configuration directory:

``` bash
cp examples/config_example.yaml ~/.cape/config.yaml
```

If that example file is not present in your project copy, skip the copy
command; CAPE can create its configuration directory on first run.

Use the interactive configuration menu, where available, to choose scan
settings, enable or disable tools, and configure custom tool paths.
Review `cape doctor` output after changing tool paths.

## Step 4: Run a first assessment

Use a target in a lab or another environment for which you have explicit
authorization. For example, if a local web application is listening on
port `3000`:

``` bash
cape scan web http://127.0.0.1:3000
cape show http://127.0.0.1:3000
cape attack http://127.0.0.1:3000 --list
```

To run an individual bounded module, use the module name shown by
`--list`, for example:

``` bash
cape attack http://127.0.0.1:3000 --module HTTPHeadersModule
```

The bounded modules display the intended check and require the operator
to type `RUN` before execution. A detected indicator is not
automatically proof of an exploitable vulnerability; review the evidence
and verify results in the lab.

## Optional: PostgreSQL setup

SQLite is suitable for a local setup. PostgreSQL support is optional and
requires the project's PostgreSQL extra.

On Kali/Debian-based systems:

``` bash
sudo apt-get install -y postgresql
```

Install the Python driver in the active virtual environment:

``` bash
python -m pip install -e ".[postgres]"
```

Create a database and user according to your local PostgreSQL policy,
then set the database connection string in your environment. For
example:

``` bash
export CAPE_DB_URL="postgresql://cape_user:YOUR_PASSWORD@localhost/cape"
```

Replace the example username, password, and database name with the
values configured on your system. Do not commit credentials to the
repository.

## Optional: Nmap capabilities

If you need Nmap raw-packet operations without running the entire CAPE
process as root, you can assign capabilities to the Nmap binary. Review
the security implications before doing so:

``` bash
sudo setcap cap_net_raw+eip "$(command -v nmap)"
sudo setcap cap_net_admin+eip "$(command -v nmap)"
```

Some scan types or tools may still require elevated privileges. Use the
least privilege necessary for the assessment.

## Verify the installation

``` bash
cape doctor
cape --version
cape scan --help
cape attack --help
```

If a command is not found, confirm that the virtual environment is
active and that the package was installed successfully:

``` bash
source .venv/bin/activate
python -m pip show cape
```

## Troubleshooting

  -----------------------------------------------------------------------
  Issue                               Suggested action
  ----------------------------------- -----------------------------------
  `cape: command not found`           Activate the virtual environment
                                      and run
                                      `python -m pip install -e .` from
                                      the project directory.

  `nmap: Permission denied`           Use an appropriate authorized
                                      privilege level or review the
                                      optional Nmap capabilities section.

  `masscan` requires elevated         Run only the required scan with the
  privileges                          privileges it needs, and only
                                      against an authorized target.

  SQLMap or Gobuster is unavailable   Install the corresponding system
                                      package if you need that
                                      external-tool path. The relevant
                                      bounded module may provide a
                                      limited fallback where documented.

  SMB checks cannot run               Install Nmap and verify that it is
                                      available on `PATH`.

  WeasyPrint/PDF rendering errors     Install the required system
                                      libraries for your distribution,
                                      including the Pango and HarfBuzz
                                      packages where applicable.

  `wpscan` API-token message          Configure a WPScan API token if the
                                      selected WPScan functionality
                                      requires one; follow WPScan's
                                      documentation.

  SQLite database locked              Avoid running concurrent CAPE
                                      processes against the same SQLite
                                      workspace/database. Consider
                                      PostgreSQL if concurrent access is
                                      required.

  Configuration file not found        Check whether `~/.cape/config.yaml`
                                      exists; copy the example
                                      configuration if it is included in
                                      the project.
  -----------------------------------------------------------------------

## Security and authorization

CAPE is intended for authorized security assessments. The
private-address restriction on the six bounded attack checks is a
technical guardrail, not proof of authorization. Obtain permission
before testing, keep checks within the agreed scope, and use isolated
lab targets when demonstrating attack-module behaviour.
