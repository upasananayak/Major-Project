"""
Complete IIoT Storage Verification System Test Runner
"""

import subprocess
import sys

def run_component(script_name, description):
    """Run a component and check if it succeeds"""
    print(f"\n{'='*20} {description} {'='*20}")
    
    try:
        result = subprocess.run([sys.executable, script_name], 
                              capture_output=True, text=True)
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        return result.returncode == 0
        
    except Exception as e:
        print(f"Error running {script_name}: {e}")
        return False

def main():
    """Run complete system test"""
    print(" IIoT Storage Verification System - Complete Test")
    print("="*70)
    
    components = [
        ("iot_simulation.py", "IoT Device Simulation"),
        ("cloud_server.py", "Cloud Server Simulation"), 
        ("verifier.py", "Verifier Simulation")
    ]
    
    success_count = 0
    
    for script, description in components:
        if run_component(script, description):
            success_count += 1
            print(f" {description} completed successfully!")
        else:
            print(f"{description} failed!")
            break
    
    print("\n" + "="*70)
    if success_count == len(components):
        print(" COMPLETE SYSTEM TEST PASSED!")
        print(" All components working correctly!")
        print(" Storage verification system fully functional!")
    else:
        print(f" System test incomplete: {success_count}/{len(components)} passed")
    print("="*70)

if __name__ == "__main__":
    main()