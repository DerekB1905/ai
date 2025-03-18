import socket
import json
import time
import random
from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import pubkey_to_G1
from py_ecc.bls.point_compression import compress_G1, decompress_G1
from py_ecc.optimized_bls12_381.optimized_curve import add, curve_order, G1, multiply, neg, normalize

def connect_to_server(host, port):
    """Connect to the server and return the socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def send_command(sock, command):
    """Send a command to the server and return the response."""
    print(f"Sending: {command}")
    sock.sendall(command.encode() + b'\n')
    
    # Wait a moment for the server to process
    time.sleep(0.1)
    
    # Receive response
    response = b""
    sock.settimeout(2.0)  # Set a timeout for receiving data
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            # If we've received a complete response, break
            if b'\n>' in chunk or b'> ' in chunk:
                break
    except socket.timeout:
        pass
    
    sock.settimeout(None)  # Reset timeout
    return response.decode()

def parse_json_response(response):
    """Parse the JSON response from the server."""
    try:
        # Find the JSON part of the response
        json_start = response.find('{')
        json_end = response.rfind('}') + 1
        if json_start >= 0 and json_end > 0:
            json_str = response[json_start:json_end]
            return json.loads(json_str)
        return None
    except json.JSONDecodeError:
        print(f"Failed to parse JSON: {response}")
        return None

def create_robot(sock):
    """Create a new robot and return its details."""
    command = '{"cmd": "create"}'
    response = send_command(sock, command)
    print(f"Create response: {response}")
    data = parse_json_response(response)
    return data

def join_robot(sock, pk):
    """Join an existing robot using its public key."""
    command = f'{{"cmd": "join", "pk": "{pk}"}}'
    response = send_command(sock, command)
    print(f"Join response: {response}")
    data = parse_json_response(response)
    return data

def hex_to_int(hex_str):
    """Convert a hex string to an integer."""
    if hex_str.startswith("0x"):
        return int(hex_str, 16)
    return int(hex_str, 16)

def verify_robot(sock, pk, robot_id, sk):
    """Verify a robot by proving we have the secret key."""
    command = f'{{"cmd": "verify", "pk": "{pk}", "robot_id": "{robot_id}"}}'
    response = send_command(sock, command)
    print(f"Verify response: {response}")
    
    # Convert the pk to bytes and the sk to integer
    pk_bytes = bytes.fromhex(pk)
    sk_int = hex_to_int(sk)
    
    # In the verification process, after sending the verify command,
    # the server expects us to handle C = x * Pk inputs directly
    
    # The server's prompt will be in the response we already received
    # We need to immediately start answering questions for 64 rounds
    
    # This appears to be stuck because we need to read from stdin
    # Let's handle the interactive part differently
    
    # The first response should include the verification instruction
    if "Prove that you have the secret key" in response:
        # Extract what the server is asking for in the input line
        input_prompt = response.splitlines()[-1].strip()
        print(f"Server asking for: {input_prompt}")
        
        # The server is waiting for our input in the format: C = x * G1 (hex)
        for i in range(64):  # 64 rounds as indicated in server code
            print(f"\nRound {i+1}/64:")
            
            # Generate a random value x
            x = random.randint(1, curve_order - 1)
            print(f"Generated random x: {x}")
            
            # Get the Pk point from the public key
            Pk_point = pubkey_to_G1(pk_bytes)
            
            # Compute C = x * Pk
            C = multiply(Pk_point, x)
            
            # Format C for sending
            C_compressed = compress_G1(C)
            C_hex = hex(C_compressed)[2:]  # Remove 0x prefix
            print(f"C = {C_hex}")
            
            # Send C to the server
            sock.sendall(f"{C_hex}\n".encode())
            
            # Get the server's request for either x or (sk + x)
            challenge = sock.recv(4096).decode().strip()
            print(f"Server challenge: {challenge}")
            
            # Check what the server is asking for
            if "Give me x (hex)" in challenge:
                # Server wants the random value x
                x_hex = hex(x)[2:]  # Remove 0x prefix
                print(f"Sending x: {x_hex}")
                sock.sendall(f"{x_hex}\n".encode())
            elif "Give me (sk + x) (hex)" in challenge:
                # Server wants sk + x
                sk_plus_x = (sk_int + x) % curve_order
                sk_plus_x_hex = hex(sk_plus_x)[2:]  # Remove 0x prefix
                print(f"Sending sk + x: {sk_plus_x_hex}")
                sock.sendall(f"{sk_plus_x_hex}\n".encode())
            else:
                print(f"Unexpected challenge: {challenge}")
                break
            
            # Check if there's any response after sending our answer
            try:
                sock.settimeout(1.0)
                feedback = sock.recv(4096).decode().strip()
                print(f"Server feedback: {feedback}")
                sock.settimeout(None)
            except socket.timeout:
                # No immediate feedback, continue to next round
                sock.settimeout(None)
                pass
    
    # After all rounds, get the final result
    try:
        sock.settimeout(2.0)
        final_result = sock.recv(4096).decode().strip()
        print(f"Final verification result: {final_result}")
        sock.settimeout(None)
    except socket.timeout:
        print("No final result received")
        sock.settimeout(None)
        final_result = ""
    
    # Parse the JSON response from the final result
    return parse_json_response(final_result)

def sign_message(sk, message):
    """Sign a message using BLS signature."""
    sk_int = hex_to_int(sk)
    return bls.Sign(sk_int, message)

def list_robots(sock, robot_id, sk):
    """List all robots registered in the system."""
    # Sign the 'list' message
    signature = sign_message(sk, b'list')
    sig_hex = signature.hex()
    
    command = f'{{"cmd": "list", "robot_id": "{robot_id}", "sig": "{sig_hex}"}}'
    response = send_command(sock, command)
    print(f"List response: {response}")
    return parse_json_response(response)

def aggregate_signatures(signatures):
    """Aggregate multiple BLS signatures."""
    return bls.Aggregate(signatures)

def unveil_secrets(sock, sk_list):
    """Try to unveil the secrets using aggregated signatures."""
    # Collect signatures from all robots
    signatures = []
    
    for i, sk in enumerate(sk_list):
        # Sign the 'unveil_secrets' message with each robot's key
        signature = sign_message(sk, b'unveil_secrets')
        signatures.append(signature)
        print(f"Generated signature for robot {i+1}")
    
    # Aggregate all signatures
    aggregated_sig = aggregate_signatures(signatures)
    sig_hex = aggregated_sig.hex()
    print(f"Aggregated signature: {sig_hex}")
    
    # Send the aggregated signature to unveil secrets
    command = f'{{"cmd": "unveil_secrets", "sig": "{sig_hex}"}}'
    response = send_command(sock, command)
    print(f"Unveil secrets response: {response}")
    return parse_json_response(response)

def main():
    host = "94.237.51.23"
    port = 50337
    
    print(f"Connecting to {host}:{port}...")
    sock = connect_to_server(host, port)
    
    # Receive the welcome message
    welcome = sock.recv(4096).decode()
    print(f"Server says: {welcome}")
    
    # Store our robots for later use
    own_robots = []
    secret_keys = []
    
    # Create a new robot
    robot_data = create_robot(sock)
    if not robot_data:
        print("Failed to create robot")
        return
    
    sk = robot_data.get("sk")
    pk = robot_data.get("pk")
    robot_id = robot_data.get("robot_id")
    
    print(f"\nRobot created successfully:")
    print(f"Secret key: {sk}")
    print(f"Public key: {pk}")
    print(f"Robot ID: {robot_id}")
    
    # Add to our list
    own_robots.append({"pk": pk, "robot_id": robot_id})
    secret_keys.append(sk)
    
    # Join another robot using the same public key
    join_data = join_robot(sock, pk)
    if not join_data:
        print("Failed to join robot")
        return
    
    joined_robot_id = join_data.get("robot_id")
    print(f"\nJoined robot ID: {joined_robot_id}")
    
    # Verify the joined robot
    verify_data = verify_robot(sock, pk, joined_robot_id, sk)
    if verify_data and "msg" in verify_data and verify_data["msg"] == "Robot verified":
        print("\nRobot verified successfully!")
        # Add to our list of controlled robots
        own_robots.append({"pk": pk, "robot_id": joined_robot_id})
        secret_keys.append(sk)  # Same secret key since we're using the same public key
    else:
        print("\nFailed to verify robot.")
    
    # List all robots in the system
    all_robots = list_robots(sock, robot_id, sk)
    if all_robots:
        print("\nAll robots in the system:", all_robots)

    # Try to unveil secrets with the robots we control
    if len(secret_keys) > 0:
        print("\nAttempting to unveil secrets with our robots...")
        secrets = unveil_secrets(sock, secret_keys)
        print("\nSecrets:", secrets)
    
    # Close the connection
    sock.close()
    print("\nConnection closed")

if __name__ == "__main__":
    main()
