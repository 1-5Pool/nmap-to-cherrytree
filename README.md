# AutoRecon Nmap XML output to CherryTree Converter

This Python script converts Nmap XML output to a CherryTree (.ctd) file format. It processes both TCP and UDP scan results, combining them into a single, easy-to-navigate CherryTree document.

## Features

- Converts Nmap XML output to CherryTree format
- Handles both TCP and UDP scan results
- Automatically searches for and includes UDP scan results
- Organizes scan results by IP address, with separate sections for TCP and UDP ports
- Includes OS detection results, port states, services, and script outputs

## Requirements

- Python 3.6 or higher
- xml.etree.ElementTree
- os
- glob
- sys

These are all standard Python libraries and should be available in most Python installations.

## Usage

1. Clone the repository:

python3 nmap_to_cherrytree.py /path/to/your/fulltcp_nmap.xml

The script will automatically look for a corresponding UDP scan file named `*top*100_udp_nmap.xml` in the same directory.

3. The output will be saved as `output.ctd` in the same directory as the input file.

## Output

The script generates a CherryTree file with the following structure:

- Root node (IP address)
- OS Detection (if available)
- TCP Ports
 - Port nodes (e.g., 22/tcp - ssh)
   - Banner information
   - Script outputs
- UDP Ports
 - Port nodes (e.g., 53/udp - domain)
   - Banner information
   - Script outputs

## License

[MIT](https://choosealicense.com/licenses/mit/)
