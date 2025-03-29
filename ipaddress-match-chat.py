import csv
import ipaddress
import sys

def load_subnet_mappings(reference_file):
    """
    Load subnet mappings from a CSV file.
    Expected format: subnet,mapping
    Example: 192.168.0.0/24,Network A
    """
    subnet_mappings = []
    print(f"Loading subnet mappings from {reference_file}")
    
    with open(reference_file, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                subnet_str, mapping = row[0], row[1]
                try:
                    subnet = ipaddress.ip_network(subnet_str, strict=False)
                    subnet_mappings.append((subnet, mapping))
                    print(f"Added mapping: {subnet} -> {mapping}")
                except ValueError:
                    print(f"Warning: Invalid subnet format: {subnet_str}")
    
    print(f"Loaded {len(subnet_mappings)} subnet mappings.")
    return subnet_mappings

def find_best_match(ip_address, subnet_mappings):
    """
    Finds the longest supernet match for the given IP address.
    The best match is the largest subnet (with the highest prefix length) that completely contains the given IP.
    """
    try:
        network = ipaddress.ip_network(ip_address, strict=False)
        ip = network.network_address
        print(f"Searching for longest supernet match for IP: {ip}")
        
        best_match = None
        longest_prefix_len = -1  # Track longest prefix length found
        
        for subnet, mapping in subnet_mappings:
            if ip in subnet:
                if subnet.prefixlen > longest_prefix_len:  # Ensure it's the longest supernet
                    longest_prefix_len = subnet.prefixlen
                    best_match = mapping
                    print(f"New longest supernet match found: {subnet} -> {mapping}")
        
        if best_match:
            print(f"Longest supernet match for {ip}: {best_match}")
        else:
            print(f"No supernet match found for {ip}")
        
        return best_match
    except ValueError:
        print(f"Invalid IP address format: {ip_address}")
        return None

def process_ips(input_file, reference_file, output_file):
    """
    Process IP addresses from input file, find matches in reference file,
    and write results to output file.
    """
    print(f"Processing IPs from {input_file}")
    subnet_mappings = load_subnet_mappings(reference_file)
    
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            ip = line.strip()
            print(f"Processing IP: {ip}")
            match = find_best_match(ip, subnet_mappings)
            
            if match:
                outfile.write(f"{ip},{match}\n")
                print(f"Written to output: {ip},{match}")
            else:
                outfile.write(f"{ip},No match found\n")
                print(f"Written to output: {ip},No match found")
    
    print(f"Processing complete. Results written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python ip_subnet_matcher.py <input_file> <reference_file> <output_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    reference_file = sys.argv[2]
    output_file = sys.argv[3]
    
    process_ips(input_file, reference_file, output_file)
