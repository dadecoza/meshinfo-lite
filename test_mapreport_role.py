#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from meshdata import MeshData
import json

# Test data based on your mapreport
test_mapreport = {
    "decoded": {
        "payload": "CglTbm9vcHkgV1MSA1NXUxgBICsqDjIuNS4yMC40Yzk3MzUxMAFAAU0AQFgcVQBAEbdYS2ARaBQ=",
        "portnum": 73,
        "json_payload": {
            "altitude": 75,
            "firmware_version": "2.5.20.4c97351",
            "has_default_channel": True,
            "hw_model": 43,
            "latitude_i": 475545600,
            "long_name": "Snoopy WS",
            "longitude_i": -1223606272,
            "num_online_local_nodes": 20,
            "position_precision": 17,
            "region": 1,
            "role": 1,
            "short_name": "SWS"
        }
    },
    "from": 0x433ae7d4,  # Convert to int
    "to": "Everyone",
    "hop_limit": 0,
    "hop_start": 0,
    "type": "mapreport"
}

def test_packet_detection():
    """Test the packet type detection logic"""
    payload = dict(test_mapreport["decoded"]["json_payload"])
    
    print("=== Packet Type Detection Test ===")
    print(f"Payload keys: {list(payload.keys())}")
    print(f"'firmware_version' in payload: {'firmware_version' in payload}")
    print(f"'role' in payload: {'role' in payload}")
    
    # Test the detection logic
    is_mapreport = "firmware_version" in payload
    is_nodeinfo = "role" in payload and "firmware_version" not in payload
    
    print(f"is_mapreport: {is_mapreport}")
    print(f"is_nodeinfo: {is_nodeinfo}")
    
    if is_mapreport:
        print("✅ Correctly detected as mapreport")
    elif is_nodeinfo:
        print("❌ Incorrectly detected as nodeinfo")
    else:
        print("❌ Not detected as either type")
    
    return is_mapreport, is_nodeinfo

def test_field_processing():
    """Test how fields are processed"""
    payload = dict(test_mapreport["decoded"]["json_payload"])
    
    print("\n=== Field Processing Test ===")
    print(f"Original role: {payload.get('role')}")
    
    # Simulate the processing logic
    is_mapreport = "firmware_version" in payload
    
    if is_mapreport:
        expected = ["hw_model", "long_name", "short_name", "firmware_version", "has_default_channel", "num_online_local_nodes", "region", "modem_preset", "role"]
        for attr in expected:
            if attr not in payload:
                payload[attr] = None
        print("✅ Processed as mapreport")
    else:
        print("❌ Not processed as mapreport")
    
    print(f"Final role: {payload.get('role')}")
    return payload.get('role')

def test_sql_logic():
    """Test the SQL CASE logic"""
    print("\n=== SQL Logic Test ===")
    
    # Simulate the SQL CASE logic
    new_role = 1  # From mapreport
    current_role = 11  # Existing in database
    
    # This is the SQL logic:
    # role = CASE 
    #     WHEN VALUES(role) IS NOT NULL THEN VALUES(role)
    #     ELSE role
    # END,
    
    if new_role is not None:
        final_role = new_role
        print(f"✅ SQL would update role from {current_role} to {final_role}")
    else:
        final_role = current_role
        print(f"❌ SQL would keep existing role {current_role}")
    
    return final_role

def test_actual_store():
    """Test the actual store_node function"""
    print("\n=== Actual Store Test ===")
    
    try:
        # Create MeshData instance
        md = MeshData()
        
        # Check current role in database
        node_id = test_mapreport["from"]
        cur = md.db.cursor(dictionary=True)
        cur.execute("SELECT role FROM nodeinfo WHERE id = %s", (node_id,))
        row = cur.fetchone()
        cur.close()
        
        if row:
            current_role = row['role']
            print(f"Current role in database: {current_role}")
        else:
            print("Node not found in database")
            return
        
        # Enable debug logging
        md.debug = True
        
        # Call store_node
        print("Calling store_node...")
        md.store_node(test_mapreport)
        
        # Check role after update
        cur = md.db.cursor(dictionary=True)
        cur.execute("SELECT role FROM nodeinfo WHERE id = %s", (node_id,))
        row = cur.fetchone()
        cur.close()
        
        if row:
            new_role = row['role']
            print(f"Role after store_node: {new_role}")
            
            if new_role == 1:
                print("✅ Role was updated correctly!")
            else:
                print(f"❌ Role was not updated. Expected 1, got {new_role}")
        else:
            print("❌ Node not found after update")
            
    except Exception as e:
        print(f"❌ Error during test: {e}")

if __name__ == "__main__":
    print("Testing mapreport role processing...")
    
    # Test packet detection
    is_mapreport, is_nodeinfo = test_packet_detection()
    
    # Test field processing
    final_role = test_field_processing()
    
    # Test SQL logic
    sql_result = test_sql_logic()
    
    print(f"\n=== Summary ===")
    print(f"Packet detected as mapreport: {is_mapreport}")
    print(f"Role after processing: {final_role}")
    print(f"SQL would set role to: {sql_result}")
    
    if is_mapreport and final_role == 1 and sql_result == 1:
        print("✅ All tests pass - role should be updated correctly")
    else:
        print("❌ Issue detected - role may not be updated correctly")
    
    # Test actual database update
    test_actual_store() 