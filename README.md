# What this is.

A program to generate large master file format zone files for testing.

It generates zones with delegations to random addresses.

It was originally designed to make zones to test signing with.

## Example Workflow.

### Requirements.

- You must have [uv](https://docs.astral.sh/uv/) installed.
- You must have [rust](https://www.rust-lang.org/tools/install) installed to build dnst.
- You must have [dnst](https://github.com/NLnetLabs/dnst) installed.
- You must have [ldns](https://www.nlnetlabs.nl/projects/ldns/about/) installed.

### Example Installation (Debian Linux)

```
$ curl -LsSf https://astral.sh/uv/install.sh | sh
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ sudo apt install ldnsutils
$ git clone git@github.com:NLnetLabs/dnst.git
$ cd dnst
$ cargo build --release
$ cargo install .
```

Then add `$HOME/.cargo/bin` to your path. I have this in my `.bash_profile`.

```
# Add users .cargo/bin to path if it exists
if [ -d "${HOME}/.cargo/bin" ]; then
    PATH=$HOME/.cargo/bin:$PATH
fi
```

### Install and use this tool.

```
$ git clone <this_repo>
$ uv sync
$ uv run generate_zone.py --help
```

## Walkthrough

Install uv, dnst, and generate_zone as above.

```
# Generating the zone to sign
$ uv run generate_zone.py --num-delegations=5000000 --base-domain=example.com --output-file=example.com --ttl=86400

# Make the KSK
$ dnst keygen --algorithm RSASHA256 -k example.com

# Make the ZSK
$ dnst keygen --algorithm RSASHA256 example.com

# Sign the zone (YOU NEED TO REPLACE THE NUMBERS WITH WHAT keygen GENERATED)
# Don't include .key or .private
$ dnst signzone -o example.com example.com Kexample.com.+008+20632 Kexample.com.+008+38175

# Verify (make sure -k specifies the .key files this time)
$ ldns-verify-zone example.com.signed -k Kexample.com.+008+20632.key -k Kexample.com.+008+38175.ke
```

## Performance Notes.

- `generate_zone.py` will use all your CPU cores to generate the zonefile.
  - Takes around 1 min to generate a 5 million delegation zonefile.
- `dnst signzone` runs in three stages.
  - Linear to load the zone (1 CPU) - quick
  - Parallel to sign the zone (all CPU's) - quick
  - Linear to link the NSEC records (1 CPU) - slow
  - Signing a 5 million delegation zonefile with NSEC took 27GB ram (peak) and around 35mins on my laptop.
- `ldns-verify-zone` 
  - Runs linearly.
  - Takes around 27GB ram (peak) and around 11mins on my laptop.
