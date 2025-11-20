import os
import json
import time
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from concurrent.futures import ThreadPoolExecutor
from threading import Thread

# Directories to monitor
directories = ['./FM1', './FM2', './FM3']

# Flag to enable/disable schema validation
ENABLE_SCHEMA_VALIDATION = True  # Set to False to disable schema validation

# ANSI color codes
BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Function to get schema for a file - this was the missing function
def get_schema_for_file(json_file_path):
    schema = {
        "required_keys": [],
        "optional_keys": [],
        "key_types": {}
    }
    
    try:
        with open(json_file_path, 'r') as json_file:
            try:
                data = json.load(json_file)
                
                if isinstance(data, list) and len(data) > 0:
                    first_element = data[0]
                    
                    # If first element is an array, it's likely a header with field names
                    if isinstance(first_element, list) and all(isinstance(x, str) for x in first_element):
                        schema["required_keys"] = first_element
                    # If first element is a dictionary, use it as a template
                    elif isinstance(first_element, dict):
                        schema["required_keys"] = list(first_element.keys())
                        for key, value in first_element.items():
                            if value is not None:
                                schema["key_types"][key] = type(value)
                
                elif isinstance(data, dict):
                    schema["required_keys"] = list(data.keys())
                    for key, value in data.items():
                        if value is not None:
                            schema["key_types"][key] = type(value)
                
                print(f"{BLUE}[INFO]{RESET} Extracted schema with {len(schema['required_keys'])} fields")
                return schema
            
            except json.JSONDecodeError:
                # If we can't parse the file, just return an empty schema
                print(f"{YELLOW}[WARNING]{RESET} Could not parse JSON to extract schema")
                return schema
    except Exception as e:
        print(f"{YELLOW}[WARNING]{RESET} Error reading file for schema extraction: {str(e)}")
        return schema

# Function to convert JSON to NDJSON with line-by-line processing for malformed JSONs
def convert_json_to_ndjson(json_file_path, ndjson_file_path):
    try:
        # Try standard JSON processing first
        with open(json_file_path, 'r') as json_file:
            data = json.load(json_file)
        
        with open(ndjson_file_path, 'w') as ndjson_file:
            schema = None
            
            if isinstance(data, list) and len(data) > 0:
                # Check if first element is an array of field names or a data object
                first_element = data[0]
                
                # If first element is an array, it's likely a header with field names
                if isinstance(first_element, list) and all(isinstance(x, str) for x in first_element):
                    # We have a list of field names as the first element
                    schema = extract_schema_from_header(first_element)
                    print(f"{BLUE}[INFO]{RESET} Found header array of field names")
                    
                    # Process remaining elements (starting from index 1)
                    valid_count = 0
                    for i, item in enumerate(data[1:], 1):
                        # For arrays, we can't directly apply field validation
                        # but we can still clean string values
                        if isinstance(item, list):
                            # Clean string values in the array
                            for j, value in enumerate(item):
                                if isinstance(value, str):
                                    item[j] = value.strip()
                            ndjson_file.write(json.dumps(item) + '\n')
                            valid_count += 1
                        else:
                            # If it's not an array, try to validate as a regular object
                            clean_object_values(item)
                            if not schema or not ENABLE_SCHEMA_VALIDATION or validate_object(item, schema):
                                ndjson_file.write(json.dumps(item) + '\n')
                                valid_count += 1
                    
                    print(f"{BLUE}[INFO]{RESET} Converted list data, used field name header, wrote {GREEN}{valid_count}{RESET} records")
                else:
                    # First element is an ordinary data object or dictionary
                    schema = extract_schema_from_header(first_element)
                    print(f"{BLUE}[INFO]{RESET} Using first object as schema template")
                    
                    # Write the data, skipping the header
                    valid_count = 0
                    for item in data[1:]:  # Start from index 1 to skip header
                        # Clean and validate against schema if available
                        if schema and ENABLE_SCHEMA_VALIDATION:
                            clean_object_values(item)  # Clean values regardless of validation
                            if not validate_object(item, schema):
                                print(f"{YELLOW}[WARNING]{RESET} Item failed schema validation, skipping")
                                continue
                        else:
                            clean_object_values(item)  # Clean values even without validation
                        
                        ndjson_file.write(json.dumps(item) + '\n')
                        valid_count += 1
                    
                    print(f"{BLUE}[INFO]{RESET} Converted list data, used first object as schema, wrote {GREEN}{valid_count}{RESET} records")
            elif isinstance(data, list) and len(data) == 0:
                print(f"{YELLOW}[WARNING]{RESET} Empty list in JSON file")
            else:
                # For non-list objects, clean and write
                clean_object_values(data)
                ndjson_file.write(json.dumps(data) + '\n')
                print(f"{BLUE}[INFO]{RESET} Converted single object data")
    except json.JSONDecodeError as e:
        print(f"{YELLOW}[WARNING]{RESET} JSON parsing error: {str(e)}")
        print(f"{BLUE}[INFO]{RESET} Attempting line-by-line processing...")
        
        # Try to recover line by line for problematic files
        valid_count = process_corrupted_json(json_file_path, ndjson_file_path)
        if valid_count > 0:
            print(f"{GREEN}[SUCCESS]{RESET} Recovered {valid_count} valid JSON objects")
        else:
            raise Exception("Failed to recover any valid JSON objects")

# Extract schema from the header (first element, which is an array of field names)
def extract_schema_from_header(header):
    schema = {
        "required_keys": [],
        "optional_keys": [],
        "key_types": {}
    }
    
    # Handle array of field names (like your provided headers)
    if isinstance(header, list):
        # Store field names as required keys
        schema["required_keys"] = header
        print(f"{BLUE}[INFO]{RESET} Extracted schema from header array with {len(schema['required_keys'])} fields")
        return schema
    
    # Handle dictionary header (original code)
    elif isinstance(header, dict):
        # Assume all keys in the header are required
        schema["required_keys"] = list(header.keys())
        
        # Record the types of each field
        for key, value in header.items():
            if value is not None:
                schema["key_types"][key] = type(value)
        
        print(f"{BLUE}[INFO]{RESET} Extracted schema from header dictionary with {len(schema['required_keys'])} fields")
        return schema
    
    # Unsupported header type
    else:
        print(f"{YELLOW}[WARNING]{RESET} Header is not a dictionary or list, cannot extract schema")
        return None

# Clean and validate an object against field names or schema
def validate_object(obj, schema):
    # First clean the object (trim strings)
    clean_object_values(obj)
    
    # Case 1: Schema contains array of field names
    # For this case, we'll validate that the object has values for these array indexes
    if isinstance(obj, list) and schema["required_keys"] and isinstance(schema["required_keys"][0], str):
        # Here we're checking a list object against field name strings, 
        # which doesn't really make sense. We'll return True as we can't validate.
        return True
    
    # Case 2: Schema contains field names and object is a dictionary
    # For this case, we don't check required keys since the data format is different
    # We just make sure it's a valid object with some data
    elif isinstance(obj, list) and len(obj) > 0:
        return True  # Accept any non-empty array
    
    # Case 3: Traditional case - object is a dictionary, schema has required keys
    elif isinstance(obj, dict):
        # Check if all required keys are present (only if they're strings)
        required_keys = [k for k in schema["required_keys"] if isinstance(k, str)]
        for key in required_keys:
            if key not in obj:
                return False
        
        # Check data types for keys that exist in the object
        for key, expected_type in schema["key_types"].items():
            if key in obj and obj[key] is not None and not isinstance(obj[key], expected_type):
                # Try to convert to the expected type
                try:
                    obj[key] = expected_type(obj[key])
                except (ValueError, TypeError):
                    return False
    
    return True

# Function to clean string values in an object (trim whitespace)
def clean_object_values(obj):
    if not isinstance(obj, dict):
        return
    
    for key, value in obj.items():
        if isinstance(value, str):
            obj[key] = value.strip()
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, str):
                    value[i] = item.strip()
                elif isinstance(item, dict):
                    clean_object_values(item)
        elif isinstance(value, dict):
            clean_object_values(value)

# Process corrupted JSON files line by line, attempting to extract valid records
def process_corrupted_json(json_file_path, ndjson_file_path):
    valid_count = 0
    schema = get_schema_for_file(json_file_path)
    
    with open(json_file_path, 'r') as f:
        content = f.read()
    
    # Extract what might be valid JSON objects (basic approach)
    # Looking for patterns like {...} with some reasonable constraints
    import re
    potential_objects = []
    
    # Try to detect if this is a JSON array with objects
    if content.strip().startswith('[') and '},' in content:
        # Split by "},", then add the closing brace back
        parts = content.split('},')
        for i, part in enumerate(parts[:-1]):  # All except the last
            if part.strip().startswith('{'):
                potential_objects.append(part + '}')
        # Handle the last part
        if parts[-1].strip().startswith('{') and parts[-1].strip().endswith('}'):
            potential_objects.append(parts[-1])
    
    with open(ndjson_file_path, 'w') as out_file:
        # Try to parse each potential object
        for obj_str in potential_objects:
            try:
                # Skip the first object (header) if this looks like an array
                if valid_count == 0 and content.strip().startswith('['):
                    valid_count += 1
                    continue
                
                # Clean up the string a bit
                obj_str = obj_str.strip()
                if not obj_str.startswith('{'):
                    obj_str = '{' + obj_str
                if not obj_str.endswith('}'):
                    obj_str = obj_str + '}'
                
                # Try to parse it
                obj = json.loads(obj_str)
                
                # Validate against schema if we have required keys
                if schema["required_keys"] and not validate_object(obj, schema):
                    print(f"{YELLOW}[WARNING]{RESET} Object failed schema validation, skipping")
                    continue
                
                out_file.write(json.dumps(obj) + '\n')
                valid_count += 1
            except json.JSONDecodeError:
                continue
    
    return valid_count

# Function to process new files
def process_file(file_path, dir_path):
    try:
        print(f"\n{BLUE}[INFO]{RESET} New JSON file detected: {os.path.basename(file_path)}")
        
        ndjson_dir = os.path.join(dir_path, 'ndjsons')
        if not os.path.exists(ndjson_dir):
            os.makedirs(ndjson_dir)
            
        ndjson_file_path = os.path.join(ndjson_dir, os.path.basename(file_path).replace('.json', '.ndjson'))
            
        if not os.path.exists(ndjson_file_path):
            convert_json_to_ndjson(file_path, ndjson_file_path)
            print(f"{GREEN}[SUCCESS]{RESET} Processed: {file_path} -> {ndjson_file_path}")
        else:
            print(f"{YELLOW}[WARNING]{RESET} File already exists: {ndjson_file_path}")
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} Error processing {file_path}: {str(e)}")

# Event handler for file system events
class JsonFileHandler(FileSystemEventHandler):
    def __init__(self, dir_path):
        self.dir_path = dir_path
        self.executor = ThreadPoolExecutor(max_workers=5)
        
    def on_created(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith('.json'):
            self.executor.submit(process_file, event.src_path, self.dir_path)

# Function to monitor directories
def monitor_directory(dir_path):
    event_handler = JsonFileHandler(dir_path)
    observer = Observer()
    observer.schedule(event_handler, path=dir_path, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Main function to start monitoring
def main():
    print(f"\n{BOLD}====== JSON to NDJSON Converter ======{RESET}")
    print(f"{BLUE}[INFO]{RESET} Starting directory monitoring service...")
    
    for directory in directories:
        if not os.path.exists(directory):
            print(f"{YELLOW}[WARNING]{RESET} Directory {directory} does not exist. Creating...")
            os.makedirs(directory)
            
        ndjson_dir = os.path.join(directory, 'ndjsons')
        if not os.path.exists(ndjson_dir):
            os.makedirs(ndjson_dir)
            
        # Start monitoring each directory in a separate thread
        monitor_thread = Thread(target=monitor_directory, args=(directory,))
        monitor_thread.daemon = True  # Allow the thread to exit when main program exits
        monitor_thread.start()
        print(f"{GREEN}[SUCCESS]{RESET} Now monitoring: {os.path.abspath(directory)}")
    
    print(f"\n{BLUE}[STATUS]{RESET} Waiting for JSON files to be added to monitored directories...")
    print(f"{YELLOW}[INFO]{RESET} Press Ctrl+C to stop the service\n")
    
    # Keep main thread running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{BLUE}[INFO]{RESET} Stopping monitoring service...")

if __name__ == "__main__":

     # Start a TCP health listener for the sensor software (default 9101)
    try:
        from health_endpoint import start_tcp_listener, start_http_status
    except Exception:
        from .health_endpoint import start_tcp_listener, start_http_status

    hp = int(os.environ.get('HEALTH_PORT', '50001'))
    ht = os.environ.get('HEALTH_TYPE', 'tcp')
    if ht.lower() == 'http':
        start_http_status(hp, path=os.environ.get('HEALTH_PATH', '/status'), name='json-to-ndjson')
    else:
        start_tcp_listener(hp, name='json-to-ndjson')

    main()

