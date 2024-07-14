import xml.etree.ElementTree as ET
import os
import glob
import sys

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    result = {}
    for host in root.findall('.//host'):
        ip = host.find('.//address[@addrtype="ipv4"]').get('addr')
        hostname = host.find('.//hostname')
        hostname = hostname.get('name') if hostname is not None else ip
        
        result[ip] = {
            'hostname': hostname,
            'tcp_ports': {},
            'udp_ports': {},
            'os': [],
            'scripts': []
        }
        
        # OS detection
        for os in host.findall('.//os/osmatch'):
            result[ip]['os'].append({
                'name': os.get('name'),
                'accuracy': os.get('accuracy')
            })
        
        # Host scripts
        for hostscript in host.findall('.//hostscript/script'):
            result[ip]['scripts'].append({
                'id': hostscript.get('id'),
                'output': hostscript.get('output')
            })
        
        for port in host.findall('.//port'):
            protocol = port.get('protocol')
            port_id = port.get('portid')
            state = port.find('state').get('state')
            service = port.find('service')
            
            port_info = {'state': state}
            
            if service is not None:
                port_info['service'] = {
                    'name': service.get('name'),
                    'product': service.get('product'),
                    'version': service.get('version'),
                    'extrainfo': service.get('extrainfo')
                }
            else:
                port_info['service'] = {'name': 'unknown'}
            
            # Port scripts
            port_info['scripts'] = []
            for script in port.findall('.//script'):
                port_info['scripts'].append({
                    'id': script.get('id'),
                    'output': script.get('output')
                })
            
            if protocol == 'tcp':
                result[ip]['tcp_ports'][port_id] = port_info
            elif protocol == 'udp':
                result[ip]['udp_ports'][port_id] = port_info
    
    return result

def generate_cherrytree_xml(nmap_data):
    root = ET.Element("cherrytree")
    
    for ip, data in nmap_data.items():
        host_node = ET.SubElement(root, "node")
        host_node.set("name", f"{data['hostname']} ({ip})")
        
        if data['os']:
            os_node = ET.SubElement(host_node, "node")
            os_node.set("name", "OS Detection")
            os_text = ET.SubElement(os_node, "rich_text")
            os_text.text = "\n".join([f"OS: {os['name']} (Accuracy: {os['accuracy']}%)" for os in data['os']])
        
        tcp_node = ET.SubElement(host_node, "node")
        tcp_node.set("name", "TCP Ports")
        
        for port, info in data['tcp_ports'].items():
            port_node = ET.SubElement(tcp_node, "node")
            port_node.set("name", f"{port}/tcp - {info['service'].get('name', 'unknown')}")
            
            banner = ET.SubElement(port_node, "rich_text")
            banner.set("weight", "heavy")
            banner.set("style", "italic")
            banner.text = "Banner:\n"
            
            banner_info = ET.SubElement(port_node, "rich_text")
            banner_info.text = f"product: {info['service'].get('product', 'N/A')} version: {info['service'].get('version', 'N/A')} extrainfo: {info['service'].get('extrainfo', 'N/A')} ostype: {info['service'].get('ostype', 'N/A')}\n"
            
            scripts = ET.SubElement(port_node, "rich_text")
            scripts.set("weight", "heavy")
            scripts.set("style", "italic")
            scripts.text = "Scripts:\n"
            
            for script in info.get('scripts', []):
                script_name = ET.SubElement(port_node, "rich_text")
                script_name.set("weight", "heavy")
                script_name.text = f"{script['id']}\n"
                
                script_output = ET.SubElement(port_node, "rich_text")
                script_output.text = f"{script['output']}\n"
        
        udp_node = ET.SubElement(host_node, "node")
        udp_node.set("name", "UDP Ports")
        
        for port, info in data.get('udp_ports', {}).items():
            port_node = ET.SubElement(udp_node, "node")
            port_node.set("name", f"{port}/udp - {info['service'].get('name', 'unknown')}")
            
            banner = ET.SubElement(port_node, "rich_text")
            banner.set("weight", "heavy")
            banner.set("style", "italic")
            banner.text = "Banner:\n"
            
            banner_info = ET.SubElement(port_node, "rich_text")
            banner_info.text = f"product: {info['service'].get('product', 'N/A')} version: {info['service'].get('version', 'N/A')} extrainfo: {info['service'].get('extrainfo', 'N/A')} ostype: {info['service'].get('ostype', 'N/A')}\n"
            
            scripts = ET.SubElement(port_node, "rich_text")
            scripts.set("weight", "heavy")
            scripts.set("style", "italic")
            scripts.text = "Scripts:\n"
            
            for script in info.get('scripts', []):
                script_name = ET.SubElement(port_node, "rich_text")
                script_name.set("weight", "heavy")
                script_name.text = f"{script['id']}\n"
                
                script_output = ET.SubElement(port_node, "rich_text")
                script_output.text = f"{script['output']}\n"
    
    return ET.tostring(root, encoding='unicode', method='xml')

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 script_name.py <path_to_input_xml>")
        sys.exit(1)

    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' does not exist.")
        sys.exit(1)

    input_dir = os.path.dirname(input_file)
    output_file = os.path.join(input_dir, "output.ctd")
    
    # Parse TCP scan results
    tcp_data = parse_nmap_xml(input_file)
    
    # Find and parse UDP scan results
    udp_files = glob.glob(os.path.join(input_dir, "*top*100_udp_nmap.xml"))
    if udp_files:
        udp_file = udp_files[0]
        udp_data = parse_nmap_xml(udp_file)
        
        # Merge UDP data into TCP data
        for ip, data in udp_data.items():
            if ip in tcp_data:
                tcp_data[ip]['udp_ports'] = data['udp_ports']
            else:
                tcp_data[ip] = data
    
    cherrytree_data = generate_cherrytree_xml(tcp_data)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(cherrytree_data)
    
    print(f"CherryTree file has been generated: {output_file}")

if __name__ == "__main__":
    main()
