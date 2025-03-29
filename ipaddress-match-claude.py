import csv          # For handling CSV file operations
import ipaddress    # Python's built-in module for IP address manipulation
import sys          # For accessing command-line arguments

def load_subnet_mappings(reference_file):
    """
    Load IP address and subnet mappings from a CSV file into memory.
    
    Parameters:
    -----------
    reference_file : str
        Path to the CSV file containing IP addresses/subnets and their mappings.
        Supports two formats in the first column:
        1. Individual IP addresses (e.g., 192.168.0.1)
        2. CIDR notation subnets (e.g., 192.168.0.0/24)
    
    Returns:
    --------
    list of tuples
        Each tuple contains (ipaddress.ip_network object, mapping string)
    
    Notes:
    ------
    - Individual IP addresses are converted to /32 (IPv4) or /128 (IPv6) subnets
    - Invalid entries will be skipped with a warning message
    """
    subnet_mappings = []  # Initialize empty list to store the IP/subnet mapping tuples
    
    print("\n--- Loading subnet mappings from reference file ---")
    
    # Open and process the reference CSV file
    with open(reference_file, 'r') as f:
        reader = csv.reader(f)  # Create CSV reader object
        line_num = 0  # Track line numbers for better debug output
        
        for row in reader:
            line_num += 1
            # Ensure the row has at least two columns (IP/subnet and mapping)
            if len(row) >= 2:
                ip_or_subnet_str, mapping = row[0], row[1]
                print(f"Line {line_num}: Processing entry '{ip_or_subnet_str}' with mapping '{mapping}'")
                
                try:
                    # First try to parse as a subnet (CIDR notation)
                    try:
                        subnet = ipaddress.ip_network(ip_or_subnet_str, strict=False)
                        print(f"  → Successfully parsed as subnet: {subnet} (prefix length: {subnet.prefixlen})")
                        subnet_mappings.append((subnet, mapping))
                    except ValueError:
                        # If not a valid subnet, try to parse as an individual IP address
                        print(f"  → Not a valid subnet, trying as individual IP address")
                        ip = ipaddress.ip_address(ip_or_subnet_str)
                        
                        # Convert individual IP to subnet with /32 (IPv4) or /128 (IPv6) mask
                        if ip.version == 4:
                            subnet = ipaddress.ip_network(f"{ip_or_subnet_str}/32")
                            print(f"  → Successfully parsed as IPv4 address and converted to /32 subnet: {subnet}")
                        else:
                            subnet = ipaddress.ip_network(f"{ip_or_subnet_str}/128")
                            print(f"  → Successfully parsed as IPv6 address and converted to /128 subnet: {subnet}")
                        
                        subnet_mappings.append((subnet, mapping))
                
                except ValueError:
                    # This exception occurs if the string is neither a valid IP nor subnet
                    print(f"  → ERROR: Invalid IP/subnet format: {ip_or_subnet_str}")
    
    print(f"\nLoaded {len(subnet_mappings)} valid subnet mappings\n")
    return subnet_mappings

def parse_ip_address(ip_str):
    """
    Parse an IP address string, which may be in CIDR notation.
    If in CIDR notation, extract just the IP portion.
    
    Parameters:
    -----------
    ip_str : str
        String containing an IP address, optionally in CIDR notation
        
    Returns:
    --------
    ipaddress.ip_address object
        The parsed IP address
    
    Raises:
    -------
    ValueError
        If the string cannot be parsed as an IP address
    """
    # Check if it's in CIDR notation
    if '/' in ip_str:
        print(f"  → Input contains slash notation: {ip_str}")
        # Extract just the IP part (before the slash)
        ip_part = ip_str.split('/')[0]
        print(f"  → Extracted IP part: {ip_part}")
        return ipaddress.ip_address(ip_part)
    else:
        # Regular IP address
        return ipaddress.ip_address(ip_str)

def find_longest_match(ip_address_str, subnet_mappings):
    """
    Find the longest matching subnet for the given IP address.
    
    Parameters:
    -----------
    ip_address_str : str
        The IP address (IPv4 or IPv6) to match
        May be in slash notation (e.g. "192.168.1.1/24")
    
    subnet_mappings : list of tuples
        List of (ip_network, mapping) tuples from the load_subnet_mappings function
    
    Returns:
    --------
    str or None
        The mapping value for the longest matching subnet or exact IP match,
        or None if no matching entry is found
    """
    try:
        # Parse the IP address, handling slash notation if present
        ip = parse_ip_address(ip_address_str)
        print(f"Finding matches for IP: {ip} (from input: {ip_address_str})")
        
        # Initialize variables to track the best match found
        longest_prefix_len = -1  # Start with an impossible prefix length
        best_match = None        # No match found yet
        best_subnet = None       # Track the actual subnet for debugging
        
        # Iterate through all IP/subnet mappings
        match_count = 0
        for subnet, mapping in subnet_mappings:
            # Check if the IP is contained within this subnet (or exact match)
            if ip in subnet:
                match_count += 1
                print(f"  → Match found: {ip} is in {subnet} (prefix length: {subnet.prefixlen}, mapping: {mapping})")
                
                # If this subnet has a longer prefix than our current best match,
                # update our best match (longer prefix = more specific match)
                if subnet.prefixlen > longest_prefix_len:
                    longest_prefix_len = subnet.prefixlen
                    best_match = mapping
                    best_subnet = subnet
                    print(f"    → New best match (more specific)")
        
        if best_match:
            print(f"Best match for {ip}: {best_subnet} (prefix length: {longest_prefix_len}) → {best_match}")
        else:
            print(f"No matches found for {ip}")
        
        print(f"Total matches found: {match_count}\n")
        return best_match
    except ValueError as e:
        print(f"ERROR: Could not parse '{ip_address_str}' as a valid IP address: {str(e)}\n")
        return None

def process_ips(input_file, reference_file, output_file):
    """
    Main processing function that:
    1. Loads IP/subnet mappings from the reference file
    2. Reads IP addresses from the input file
    3. Finds the best match for each IP from the reference file
    4. Writes the results to the output file
    
    Parameters:
    -----------
    input_file : str
        Path to the input file containing IP addresses (one per line)
        Supports both plain IP addresses and CIDR notation
    
    reference_file : str
        Path to the CSV file containing IP/subnet mappings
    
    output_file : str
        Path to the output file where results will be written in CSV format
    
    Notes:
    ------
    - Output format is: ip_address,mapping
    - If no match is found, "No match found" will be written as the mapping
    - For input IPs in CIDR notation, the original notation is preserved in the output
    """
    # First, load all IP/subnet mappings from the reference file
    subnet_mappings = load_subnet_mappings(reference_file)
    
    print("--- Processing IP addresses from input file ---")
    
    # Process each IP and write results to the output file
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        ip_count = 0
        match_count = 0
        
        for line in infile:
            ip_count += 1
            # Strip whitespace (including newlines) from the IP address
            ip = line.strip()
            print(f"Processing IP #{ip_count}: {ip}")
            
            # Find the best matching IP/subnet for this input IP
            match = find_longest_match(ip, subnet_mappings)
            
            # Write the result to the output file
            if match:
                match_count += 1
                outfile.write(f"{ip},{match}\n")
                print(f"Result written: {ip},{match}")
            else:
                outfile.write(f"{ip},No match found\n")
                print(f"Result written: {ip},No match found")
    
    print(f"\n--- Summary ---")
    print(f"Total IPs processed: {ip_count}")
    print(f"IPs with matches: {match_count}")
    print(f"IPs without matches: {ip_count - match_count}")

# Script entry point - this block executes when the script is run directly
if __name__ == "__main__":
    # Check if the correct number of command line arguments were provided
    if len(sys.argv) != 4:
        # Print usage information if incorrect arguments were provided
        print("Usage: python ip_subnet_matcher.py <input_file> <reference_file> <output_file>")
        sys.exit(1)  # Exit with an error code
    
    # Parse command line arguments
    input_file = sys.argv[1]      # File containing IP addresses to match
    reference_file = sys.argv[2]  # CSV file with IP/subnet mappings
    output_file = sys.argv[3]     # Output file to write results
    
    print(f"\nRunning IP subnet matcher")
    print(f"Input file: {input_file}")
    print(f"Reference file: {reference_file}")
    print(f"Output file: {output_file}")
    
    # Call the main processing function
    process_ips(input_file, reference_file, output_file)
    
    # Print completion message
    print(f"\nProcessing complete. Results written to {output_file}")