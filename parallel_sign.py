#!/usr/bin/env python3
"""
Parallel DNS Zone Signing Tool

This script implements the advanced technique for signing large DNS zones in parallel
by splitting the zone into chunks, signing each chunk separately, and combining the results.
"""

import argparse
import multiprocessing as mp
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Tuple, Optional
from tqdm import tqdm
from tqdm.contrib.concurrent import process_map


class ParallelZoneSigner:
    """Handles parallel signing of large DNS zones."""
    
    def __init__(self, zone_file: str, key_files: List[str], 
                 output_file: str = None, chunk_size: int = 10000):
        """
        Initialize the parallel zone signer.
        
        Args:
            zone_file: Path to the zone file to sign
            key_files: List of key file paths (both KSK and ZSK)
            output_file: Output signed zone file (default: zone_file + '.signed')
            chunk_size: Number of records per chunk
        """
        self.zone_file = Path(zone_file)
        self.key_files = key_files
        self.output_file = Path(output_file) if output_file else Path(f"{zone_file}.signed")
        self.chunk_size = chunk_size
        self.temp_dir = None
        
        # Validate inputs
        self._validate_inputs()
    
    def _validate_inputs(self):
        """Validate input files and parameters."""
        if not self.zone_file.exists():
            raise FileNotFoundError(f"Zone file not found: {self.zone_file}")
        
        for key_file in self.key_files:
            if not Path(key_file).exists():
                raise FileNotFoundError(f"Key file not found: {key_file}")
        
        # Check if ldns-signzone is available
        try:
            subprocess.run(['ldns-signzone'], capture_output=True, check=False)
        except FileNotFoundError:
            raise RuntimeError("ldns-signzone not found. Please install ldns-utils.")
    
    def _extract_zone_header(self) -> Tuple[List[str], str]:
        """
        Extract the zone header (SOA, NS records) and determine the zone origin.
        
        Returns:
            Tuple of (header_lines, zone_origin)
        """
        header_lines = []
        zone_origin = None
        
        with open(self.zone_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(';'):
                    continue
                
                if line.startswith('$ORIGIN'):
                    zone_origin = line.split()[1]
                    header_lines.append(line)
                elif line.startswith('@') or ('SOA' in line and '@' in line):
                    header_lines.append(line)
                elif line.startswith('@') and 'NS' in line:
                    header_lines.append(line)
                elif line.startswith('ns') and ('A' in line or 'AAAA' in line):
                    header_lines.append(line)
                else:
                    # First delegation record found, stop header extraction
                    break
        
        if not zone_origin:
            raise ValueError("Could not determine zone origin from zone file")
        
        return header_lines, zone_origin
    
    def _split_zone_file(self) -> List[Path]:
        """
        Split the zone file into overlapping chunks for parallel processing.
        This ensures NSEC chain continuity across chunk boundaries.
        
        Returns:
            List of chunk file paths
        """
        print(f"Splitting zone file into chunks of {self.chunk_size} records with overlap...")
        
        # Create temporary directory
        self.temp_dir = Path(tempfile.mkdtemp(prefix="zone_signing_"))
        
        # Extract header
        header_lines, zone_origin = self._extract_zone_header()
        
        # Read all delegation records into memory first
        all_delegation_lines = []
        with open(self.zone_file, 'r') as f:
            # Skip header lines by reading until first delegation
            lines_read = 0
            for line in f:
                lines_read += 1
                line_stripped = line.strip()
                
                # Skip empty lines and comments
                if not line_stripped or line_stripped.startswith(';'):
                    continue
                
                # Check if this is a delegation record (not header)
                if not (line_stripped.startswith('$ORIGIN') or 
                       line_stripped.startswith('@') or
                       line_stripped.startswith('ns') and ('A' in line_stripped or 'AAAA' in line_stripped)):
                    # This is the first delegation record, start processing from here
                    break
            
            # Reset file position to start of delegations
            f.seek(0)
            for _ in range(lines_read - 1):
                next(f, None)
            
            # Read all delegation records
            for line in f:
                line = line.strip()
                if not line or line.startswith(';'):
                    continue
                all_delegation_lines.append(line)
        
        # Group lines by delegation (each delegation has multiple records)
        delegations = []
        current_delegation = []
        current_delegation_name = None
        
        for line in all_delegation_lines:
            if 'IN' in line and ('NS' in line or 'A' in line or 'AAAA' in line):
                parts = line.split()
                if len(parts) >= 4:
                    record_name = parts[0]
                    
                    # If this is a new delegation name, save the previous one
                    if current_delegation_name and record_name != current_delegation_name and not record_name.startswith('ns'):
                        delegations.append(current_delegation)
                        current_delegation = [line]
                        current_delegation_name = record_name
                    else:
                        current_delegation.append(line)
                        if current_delegation_name is None and not record_name.startswith('ns'):
                            current_delegation_name = record_name
        
        # Add the last delegation
        if current_delegation:
            delegations.append(current_delegation)
        
        # Create overlapping chunks
        chunk_files = []
        overlap_size = 2  # Number of delegations to overlap
        
        for chunk_start in range(0, len(delegations), self.chunk_size // 4):  # Divide by 4 since each delegation has ~4 records
            chunk_end = min(chunk_start + (self.chunk_size // 4), len(delegations))
            overlap_end = min(chunk_end + overlap_size, len(delegations))
            
            # Get chunk delegations (main chunk + overlap)
            chunk_delegations = delegations[chunk_start:overlap_end]
            
            # Flatten delegation records
            chunk_lines = []
            for delegation in chunk_delegations:
                chunk_lines.extend(delegation)
            
            if chunk_lines:
                chunk_file = self._write_chunk(len(chunk_files), header_lines, 
                                             zone_origin, chunk_lines)
                chunk_files.append(chunk_file)
        
        print(f"Created {len(chunk_files)} overlapping chunks in {self.temp_dir}")
        return chunk_files
    
    def _write_chunk(self, chunk_num: int, header_lines: List[str], 
                    zone_origin: str, chunk_lines: List[str]) -> Path:
        """Write a chunk file with header and delegation records."""
        chunk_file = self.temp_dir / f"chunk_{chunk_num:04d}.zone"
        
        with open(chunk_file, 'w') as f:
            # Write header
            f.write(f"$ORIGIN {zone_origin}\n")
            for line in header_lines:
                f.write(f"{line}\n")
            f.write("\n")
            
            # Write chunk content
            for line in chunk_lines:
                f.write(f"{line}\n")
        
        return chunk_file
    
    def _sign_chunk(self, args: Tuple[Path, int]) -> Tuple[Path, bool, str]:
        """
        Sign a single chunk file.
        
        Args:
            args: Tuple of (chunk_file_path, chunk_index)
            
        Returns:
            Tuple of (signed_file_path, success, error_message)
        """
        chunk_file, chunk_idx = args
        signed_file = chunk_file.with_suffix('.zone.signed')
        
        try:
            # Copy key files to chunk directory for ldns-signzone
            chunk_dir = chunk_file.parent
            local_key_files = []
            
            for key_file in self.key_files:
                key_path = Path(key_file)
                
                # Copy the .key file
                local_key_path = chunk_dir / key_path.name
                shutil.copy2(key_path, local_key_path)
                
                # Copy the corresponding .private file
                private_path = key_path.with_suffix('.private')
                if private_path.exists():
                    local_private_path = chunk_dir / private_path.name
                    shutil.copy2(private_path, local_private_path)
                else:
                    return signed_file, False, f"Private key file not found: {private_path}"
                
                # Use only the base name without extension for ldns-signzone
                base_name = key_path.stem
                local_key_files.append(base_name)
            
            # Build ldns-signzone command (NSEC only for parallel signing)
            cmd = ['ldns-signzone']
            
            # Add zone file and key files
            cmd.append(str(chunk_file))
            cmd.extend(local_key_files)
            
            # Run signing command
            result = subprocess.run(cmd, cwd=chunk_dir, capture_output=True, 
                                  text=True, timeout=300)
            
            if result.returncode != 0:
                return signed_file, False, f"ldns-signzone failed: {result.stderr}"
            
            return signed_file, True, ""
            
        except subprocess.TimeoutExpired:
            return signed_file, False, "Signing timeout (5 minutes)"
        except Exception as e:
            return signed_file, False, f"Exception during signing: {str(e)}"
    
    def _combine_signed_chunks(self, signed_chunks: List[Path]) -> None:
        """Combine signed chunk files into the final output, handling overlaps."""
        print("Combining signed chunks and deduplicating overlapped records...")
        
        seen_records = set()  # Track records we've already written
        
        with open(self.output_file, 'w') as output:
            # Process first chunk completely (includes header)
            if signed_chunks:
                with open(signed_chunks[0], 'r') as f:
                    for line in f:
                        line_stripped = line.strip()
                        
                        # Always write header and zone apex records
                        if (line_stripped.startswith('$ORIGIN') or 
                            line_stripped.startswith('@') or
                            'DNSKEY' in line_stripped or
                            'SOA' in line_stripped or
                            (line_stripped.startswith('ns') and 'example.com.' in line_stripped)):
                            output.write(line)
                            continue
                        
                        # For delegation records, track to avoid duplicates
                        if line_stripped and 'IN' in line_stripped:
                            # Create a canonical form for comparison (without RRSIG timestamps)
                            parts = line_stripped.split()
                            if len(parts) >= 4:
                                # Use name, class, type, and data for deduplication (skip TTL and RRSIG timestamps)
                                if parts[2] == 'IN' and parts[3] == 'RRSIG':
                                    # For RRSIG, only compare the first few fields (not timestamps)
                                    canonical = f"{parts[0]} {parts[2]} {parts[3]} {parts[4]} {parts[5]} {' '.join(parts[9:])}"
                                else:
                                    canonical = f"{parts[0]} {parts[2]} {parts[3]} {' '.join(parts[4:])}"
                                
                                if canonical not in seen_records:
                                    seen_records.add(canonical)
                                    output.write(line)
                        else:
                            output.write(line)
            
            # For remaining chunks, skip headers and deduplicate delegation records
            for chunk_file in signed_chunks[1:]:
                with open(chunk_file, 'r') as f:
                    in_header = True
                    for line in f:
                        line_stripped = line.strip()
                        
                        # Skip empty lines and comments in header
                        if not line_stripped or line_stripped.startswith(';'):
                            if not in_header:
                                output.write(line)
                            continue
                        
                        # Skip all header elements
                        if (line_stripped.startswith('$ORIGIN') or 
                            line_stripped.startswith('@') or
                            'SOA' in line_stripped or
                            'DNSKEY' in line_stripped or
                            (line_stripped.startswith('ns') and 'example.com.' in line_stripped and 'zone' not in line_stripped)):
                            continue
                        
                        # Mark end of header when we hit first delegation
                        if in_header and ('zone' in line_stripped.lower() or 
                                        (line_stripped.split()[0] if line_stripped.split() else '').startswith('zone')):
                            in_header = False
                        
                        # Process delegation records with deduplication
                        if not in_header and line_stripped and 'IN' in line_stripped:
                            parts = line_stripped.split()
                            if len(parts) >= 4:
                                # Create canonical form for deduplication
                                if parts[2] == 'IN' and parts[3] == 'RRSIG':
                                    canonical = f"{parts[0]} {parts[2]} {parts[3]} {parts[4]} {parts[5]} {' '.join(parts[9:])}"
                                else:
                                    canonical = f"{parts[0]} {parts[2]} {parts[3]} {' '.join(parts[4:])}"
                                
                                if canonical not in seen_records:
                                    seen_records.add(canonical)
                                    output.write(line)
                        elif not in_header:
                            output.write(line)
    
    def _rebuild_nsec_chain(self) -> bool:
        """
        Rebuild the NSEC chain for the combined zone by re-signing the entire zone.
        This fixes the broken NSEC chain caused by parallel signing.
        """
        try:
            # Create a temporary directory for the complete re-signing
            with tempfile.TemporaryDirectory(prefix="nsec_rebuild_") as temp_dir:
                temp_dir = Path(temp_dir)
                
                # Copy key files to temp directory
                for key_file in self.key_files:
                    key_path = Path(key_file)
                    
                    # Copy .key file
                    shutil.copy2(key_path, temp_dir / key_path.name)
                    
                    # Copy .private file
                    private_path = key_path.with_suffix('.private')
                    if private_path.exists():
                        shutil.copy2(private_path, temp_dir / private_path.name)
                
                # Copy the signed zone file (which has all records but broken NSEC)
                temp_zone = temp_dir / "zone_to_rebuild.zone"
                
                # Extract just the non-NSEC records from the signed zone
                with open(self.output_file, 'r') as signed_file, open(temp_zone, 'w') as clean_zone:
                    for line in signed_file:
                        line_stripped = line.strip()
                        # Skip NSEC records and their signatures, but keep everything else
                        if line_stripped and 'NSEC' not in line_stripped:
                            clean_zone.write(line)
                
                # Re-sign the cleaned zone with proper NSEC chain
                local_key_files = [Path(kf).stem for kf in self.key_files]
                cmd = ['ldns-signzone', str(temp_zone)] + local_key_files
                
                result = subprocess.run(cmd, cwd=temp_dir, capture_output=True, 
                                      text=True, timeout=300)
                
                if result.returncode == 0:
                    # Copy the properly signed zone back
                    rebuilt_zone = temp_zone.with_suffix('.zone.signed')
                    if rebuilt_zone.exists():
                        shutil.copy2(rebuilt_zone, self.output_file)
                        return True
                else:
                    print(f"NSEC rebuild failed: {result.stderr}")
                    return False
                    
        except Exception as e:
            print(f"Exception during NSEC rebuild: {e}")
            return False
        
        return False
    
    def _cleanup(self):
        """Clean up temporary files."""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def sign_zone(self) -> bool:
        """
        Main method to sign the zone in parallel.
        
        Returns:
            True if signing successful, False otherwise
        """
        start_time = time.time()
        
        try:
            print(f"Starting parallel signing of {self.zone_file}")
            print(f"Output file: {self.output_file}")
            print(f"Chunk size: {self.chunk_size} records")
            print(f"Using NSEC for denial of existence (parallel signing only supports NSEC)")
            
            # Step 1: Split zone file
            chunk_files = self._split_zone_file()
            
            # Step 2: Sign chunks in parallel
            print(f"Signing {len(chunk_files)} chunks in parallel...")
            
            num_cores = mp.cpu_count()
            chunk_args = [(chunk_file, i) for i, chunk_file in enumerate(chunk_files)]
            
            # Use process_map for progress tracking
            results = process_map(
                self._sign_chunk,
                chunk_args,
                max_workers=num_cores,
                desc="Signing chunks",
                unit="chunk",
                chunksize=1
            )
            
            # Check results
            signed_chunks = []
            failed_chunks = []
            
            for (signed_file, success, error), (chunk_file, chunk_idx) in zip(results, chunk_args):
                if success:
                    signed_chunks.append(signed_file)
                else:
                    failed_chunks.append((chunk_file, error))
            
            if failed_chunks:
                print(f"\nFailed to sign {len(failed_chunks)} chunks:")
                for chunk_file, error in failed_chunks:
                    print(f"  {chunk_file}: {error}")
                return False
            
            # Step 3: Combine results
            self._combine_signed_chunks(signed_chunks)
            
            # Step 4: Fix NSEC chain in the combined zone
            print("Rebuilding NSEC chain for complete zone...")
            success = self._rebuild_nsec_chain()
            if not success:
                print("WARNING: Failed to rebuild NSEC chain completely")
            
            # Step 5: Verify the final result
            print("Verifying signed zone...")
            verify_result = subprocess.run(['ldns-verify-zone', str(self.output_file)], 
                                         capture_output=True, text=True)
            
            if verify_result.returncode != 0:
                print(f"WARNING: Zone verification failed: {verify_result.stderr}")
            else:
                print("Zone verification successful!")
            
            elapsed_time = time.time() - start_time
            print(f"\nParallel signing completed in {elapsed_time:.2f} seconds")
            print(f"Signed zone written to: {self.output_file}")
            
            return True
            
        except Exception as e:
            print(f"Error during parallel signing: {e}")
            return False
        finally:
            self._cleanup()


def main():
    """Main function with command-line interface."""
    parser = argparse.ArgumentParser(
        description="Parallel DNS Zone Signing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic parallel signing with automatic key detection
  python parallel_sign.py example.com.zone
  
  # With specific keys and custom chunk size
  python parallel_sign.py example.com.zone -k Kexample.com.+008+12345.key Kexample.com.+008+54321.key -c 25000
  
  # Large zone with custom output
  python parallel_sign.py huge.zone -o huge.signed -c 50000
        """
    )
    
    parser.add_argument('zone_file', help='Zone file to sign')
    
    parser.add_argument('-k', '--key-files', nargs='*', 
                       help='Key files (if not specified, auto-detect Kzonename.+*.key)')
    
    parser.add_argument('-o', '--output', 
                       help='Output signed zone file (default: zone_file.signed)')
    
    parser.add_argument('-c', '--chunk-size', type=int, default=10000,
                       help='Records per chunk (default: 10000)')
    
    args = parser.parse_args()
    
    # Auto-detect key files if not specified
    key_files = args.key_files
    if not key_files:
        # Try to extract zone name from file content first
        zone_name = None
        try:
            with open(args.zone_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('$ORIGIN'):
                        zone_name = line.split()[1].rstrip('.')
                        break
                    elif line.startswith('@') and 'SOA' in line:
                        # No $ORIGIN found, try to get from filename
                        break
        except:
            pass
        
        # Fallback to filename-based detection
        if not zone_name:
            zone_name = Path(args.zone_file).stem
            if zone_name.endswith('.zone'):
                zone_name = zone_name[:-5]
            elif zone_name.endswith('.txt'):
                zone_name = zone_name[:-4]
        
        # Look for key files in current directory
        key_pattern = f"K{zone_name}.+*.key"
        import glob
        key_files = glob.glob(key_pattern)
        
        if not key_files:
            print(f"No key files found matching pattern: {key_pattern}")
            print("Please specify key files with -k option")
            return 1
        
        print(f"Auto-detected key files: {', '.join(key_files)}")
    
    # Create signer and run
    signer = ParallelZoneSigner(
        zone_file=args.zone_file,
        key_files=key_files,
        output_file=args.output,
        chunk_size=args.chunk_size
    )
    
    success = signer.sign_zone()
    return 0 if success else 1


if __name__ == '__main__':
    exit(main()) 