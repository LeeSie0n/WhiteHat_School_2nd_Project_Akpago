import os
import subprocess
import csv
import re
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

def parse_capa_output(output):
    parsed_data = {
        'ATT&CK Tactic': [],
        'ATT&CK Technique': [],
        'MBC Objective': [],
        'MBC Behavior': [],
        'Namespace': [],
        'Capability': []
    }
    
    sections = output.split('\n\n')
    for idx, section in enumerate(sections):
        lines = section.strip().split('\n')
        if not lines:
            continue
        
        if idx != 0:
            current_capability = lines[0].strip()
            parsed_data['Capability'].append(current_capability)
        
        for line in lines[1:] if idx != 0 else lines:
            if 'namespace' in line:
                namespace_match = re.search(r'namespace\s+(\S+)', line)
                if namespace_match:
                    parsed_data['Namespace'].append(namespace_match.group(1).strip())

            if 'mbc' in line:
                mbc_match = re.search(r'mbc\s+([^\:]+)\s*\:\s*([^,\n]+)', line, re.IGNORECASE)
                if mbc_match:
                    parsed_data['MBC Objective'].append(mbc_match.group(1).strip())
                    parsed_data['MBC Behavior'].append(mbc_match.group(2).strip())

            if 'att&ck' in line:
                attack_match = re.search(r'att&ck\s+([^\:]+)\s*\:\s*([^,\n]+)', line, re.IGNORECASE)
                if attack_match:
                    parsed_data['ATT&CK Tactic'].append(attack_match.group(1).strip())
                    parsed_data['ATT&CK Technique'].append(attack_match.group(2).strip())

    for key in parsed_data:
        parsed_data[key] = '; '.join(set(parsed_data[key]))

    return parsed_data

def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return entropy

def process_file(capa_path, file_path):
    try:
        print('Processing:', file_path)
        result = subprocess.run([capa_path, '-vv', file_path], capture_output=True, text=True, encoding='utf-8')
        if result.stdout:
            parsed_data = parse_capa_output(result.stdout)
            parsed_data['file_name'] = os.path.basename(file_path)
            parsed_data['Entropy'] = calculate_entropy(file_path)
            return parsed_data
        else:
            print(f"No output from capa for file: {file_path}")
    except subprocess.CalledProcessError as e:
        print(f"Capa failed to run on {file_path}: {str(e)}")
    return None

def run_capa_and_save_to_csv(input_directory, output_csv_path, max_workers):
    capa_path = r"/home/bigdata/Downloads/capa-v7.0.1-linux/capa"

    processed_files = set()
    if os.path.exists(output_csv_path):
        with open(output_csv_path, 'r', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                processed_files.add(row['file_name'])

    with open(output_csv_path, 'a', newline='', encoding='utf-8') as file:
        fieldnames = ['file_name', 'Entropy', 'ATT&CK Tactic', 'ATT&CK Technique', 'MBC Objective', 'MBC Behavior', 'Namespace', 'Capability']
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        if not processed_files:
            writer.writeheader()
        
        file_paths = [
            os.path.join(root, filename)
            for root, dirs, files in os.walk(input_directory)
            for filename in files
        ]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for file_path in file_paths:
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                
                if file_name in processed_files:
                    print(f"Already did: {file_name}")
                elif file_size > 2 * 1024 * 1024:  # File size is larger than 2MB
                    print(f"Except Capa: {file_name} ({file_size} bytes)")
                else:
                    futures[executor.submit(process_file, capa_path, file_path)] = file_name

            for future in as_completed(futures):
                result = future.result()
                if result:
                    writer.writerow(result)
                    processed_files.add(result['file_name'])
    print('Done')

input_directory = r"/home/bigdata/Desktop/dataset/6. 대용량_정상,악성파일Ⅳ (2019)/4_dataset/3.finalSet1"
output_csv_path = r"Capa_Version_02_File_6_4_3.csv"
print('Starting')
run_capa_and_save_to_csv(input_directory, output_csv_path, 5)
