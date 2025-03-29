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
        superset_match = None
        longest_prefix_len_superset = -1
        
        # Search for the longest match and the longest superset
        for subnet, mapping in subnet_mappings:
            if ip in subnet:
                if subnet.prefixlen > longest_prefix_len:  # Ensure it's the longest supernet
                    longest_prefix_len = subnet.prefixlen
                    best_match = mapping
                    print(f"New longest supernet match found: {subnet} -> {mapping}")
            if subnet.supernet_of(network):
                if subnet.prefixlen > longest_prefix_len_superset:  # Ensure it's the longest superset
                    longest_prefix_len_superset = subnet.prefixlen
                    superset_match = mapping
                    print(f"New longest superset match found: {subnet} -> {mapping}")
        
        if best_match and superset_match:
            print(f"Longest supernet match for {ip}: {best_match}, Longest superset match: {superset_match}")
        elif best_match:
            print(f"Longest supernet match for {ip}: {best_match}, No superset match found.")
        elif superset_match:
            print(f"No supernet match found for {ip}, Longest superset match: {superset_match}")
        else:
            print(f"No match found for {ip}")
        
        return best_match, superset_match
    except ValueError:
        print(f"Invalid IP address format: {ip_address}")
        return None, None

def process_ips(input_file, reference_file, output_file):
    """
    Process IP addresses from input file, find matches in reference file,
    and write results to output file.
    """
    print(f"Processing IPs from {input_file}")
    subnet_mappings = load_subnet_mappings(reference_file)
    
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        # Writing header to output file
        outfile.write("original-ip,ref-longest-match,ref-superset-match\n")
        
        for line in infile:
            ip = line.strip()
            print(f"Processing IP: {ip}")
            best_match, superset_match = find_best_match(ip, subnet_mappings)
            
            # Write the original IP, the longest prefix match, and the superset match to the output file
            if best_match:
                outfile.write(f"{ip},{best_match}")
                print(f"Written to output: {ip},{best_match}")
            else:
                outfile.write(f"{ip},No match found")
                print(f"Written to output: {ip},No match found")

            if superset_match:
                outfile.write(f",{superset_match}\n")
                print(f"Written to output: {ip},{superset_match}")
            else:
                outfile.write(f",No superset match\n")
                print(f"Written to output: {ip},No superset match")
    
    print(f"Processing complete. Results written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python ip_subnet_matcher.py <input_file> <reference_file> <output_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    reference_file = sys.argv[2]
    output_file = sys.argv[3]
    
    process_ips(input_file, reference_file, output_file)
