#!/usr/bin/env python3
"""
Setup script for PhishShield Backend
"""
import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"\n📦 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error in {description}: {e}")
        print(f"Error output: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8 or higher is required")
        print(f"Current version: {version.major}.{version.minor}.{version.micro}")
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} is compatible")
    return True

def main():
    print("=" * 60)
    print("🛡️  PhishShield Backend Setup")
    print("=" * 60)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not run_command(
        "pip install -r requirements.txt",
        "Installing dependencies"
    ):
        print("\n💡 Try running: pip install --upgrade pip")
        print("Then run this script again")
        sys.exit(1)
    
    # Create necessary directories
    directories = ["models", "data", "logs"]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created directory: {directory}")
    
    # Test the installation
    print("\n🧪 Testing installation...")
    if not run_command(
        "python test_backend.py",
        "Testing backend components"
    ):
        print("\n❌ Installation test failed")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("🎉 Setup completed successfully!")
    print("\n📋 Next steps:")
    print("   1. Start the server: python start.py")
    print("   2. Open browser: http://localhost:8000/docs")
    print("   3. Test the API endpoints")
    print("=" * 60)

if __name__ == "__main__":
    main()
