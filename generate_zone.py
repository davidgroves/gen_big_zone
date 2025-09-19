#!/usr/bin/env python3

import argparse
import ipaddress
import random
import multiprocessing as mp

from tqdm.contrib.concurrent import process_map

def generate_random_ipv4() -> str:
    """Generate a random private IPv4 address."""
    private_ranges = [
        ipaddress.IPv4Network('10.0.0.0/8'),
        ipaddress.IPv4Network('172.16.0.0/12'),
        ipaddress.IPv4Network('192.168.0.0/16')
    ]
    
    network = random.choice(private_ranges)
    host = random.randint(1, int(network.num_addresses) - 2)
    return str(network[host])

def generate_random_ipv6() -> str:
    """Generate a random ULA IPv6 address."""
    # Generate fd00::/8 unique local address
    # Create a proper IPv6 address with 8 groups
    groups = [0xfd00] + [random.randint(0, 0xffff) for _ in range(7)]
    return ':'.join(f'{group:04x}' for group in groups)

def generate_delegation_chunk_simple(args):
    """Generate a chunk of delegations and return the text representation."""
    start_idx, end_idx, base_domain, ttl = args
    
    # Ensure base domain is fully qualified
    if not base_domain.endswith('.'):
        base_domain = base_domain + '.'
    
    lines = []
    
    for i in range(start_idx, end_idx):
        # Create delegation name (e.g., zone1, zone2, etc.)
        deleg_name = f'zone{i+1}'
        target_domain = f'{deleg_name}.{base_domain}'
        
        # Create NS records for delegation
        for j in range(4):
            ns_name = f'ns{j}.{target_domain}'
            if not ns_name.endswith('.'):
                ns_name = ns_name + '.'
            lines.append(f'{deleg_name} {ttl} IN NS {ns_name}')
            
            # Add glue records
            ipv4_addr = generate_random_ipv4()
            ipv6_addr = generate_random_ipv6()
            lines.append(f'ns{j}.{deleg_name} {ttl} IN A {ipv4_addr}')
            lines.append(f'ns{j}.{deleg_name} {ttl} IN AAAA {ipv6_addr}')
    
    return '\n'.join(lines)

def create_zone_file(num_delegations: int, base_domain: str, output_file: str, ttl: int = 86400):
    """Create a zone file with the specified number of delegations using multiprocessing."""
    
    # Ensure base domain is fully qualified
    if not base_domain.endswith('.'):
        base_domain = base_domain + '.'
    
    # Get number of CPU cores
    num_cores = mp.cpu_count()
    print(f"Using {num_cores} CPU cores for parallel processing")
    
    # Calculate chunk size: either 1000 names or 0.2% of total, whichever is greater
    chunk_size_by_count = 1000
    chunk_size_by_percentage = max(1, int(num_delegations * 0.002))  # 0.2%
    chunk_size = max(chunk_size_by_count, chunk_size_by_percentage)
    
    # Create argument tuples for each process
    process_args = []
    for i in range(0, num_delegations, chunk_size):
        start_idx = i
        end_idx = min(i + chunk_size, num_delegations)
        process_args.append((start_idx, end_idx, base_domain, ttl))
    
    # Generate delegations in parallel with progress bar
    print(f"Generating {num_delegations} delegations in {len(process_args)} chunks...")
    
    # Use tqdm's built-in multiprocessing support
    delegation_chunks = process_map(
        generate_delegation_chunk_simple,
        process_args,
        max_workers=num_cores,
        desc="Generating delegations",
        unit="chunk",
        chunksize=1
    )
    
    # Create the header with SOA and base NS records
    header_lines = [
        f'$ORIGIN {base_domain}',
        f'@ {ttl} IN SOA ns0 hostmaster 2023091800 7200 3600 1209600 {ttl}',
    ]
    
    # Add NS records for the base domain
    for i in range(4):
        header_lines.append(f'@ {ttl} IN NS ns{i}')
        # Add A and AAAA records for base nameservers
        header_lines.append(f'ns{i} {ttl} IN A {generate_random_ipv4()}')
        header_lines.append(f'ns{i} {ttl} IN AAAA {generate_random_ipv6()}')
    
    # Write the complete zone file
    print(f"Writing zone file to {output_file}...")
    with open(output_file, 'w') as f:
        # Write header
        f.write('\n'.join(header_lines))
        f.write('\n')
        
        # Write delegation chunks
        for chunk in delegation_chunks:
            if chunk.strip():  # Only write non-empty chunks
                f.write(chunk)
                f.write('\n')

def main():
    parser = argparse.ArgumentParser(description='Generate a DNS zone file with delegations')
    parser.add_argument('--num-delegations', type=int, default=500, help='Number of delegations to create (default: 500)')
    parser.add_argument('--base-domain', default='example.com', help='Base domain name (default: example.com)')
    parser.add_argument('--output-file', default='out.txt', help='Output file name (default: out.txt)')
    parser.add_argument('--ttl', type=int, default=86400, help='TTL for all records (default: 86400)')
    
    args = parser.parse_args()
    
    create_zone_file(args.num_delegations, args.base_domain, args.output_file, args.ttl)
    print(f"\nZone file has been written to {args.output_file}")

if __name__ == '__main__':
    main()
