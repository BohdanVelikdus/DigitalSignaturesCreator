import subprocess
import os
import platform

def run_conan(os_type_str):
    try:
        # Install dependencies for Debug build
        #subprocess.run([
        #    "conan", "install", ".", 
        #    "--build=missing", 
        #    "--output-folder=./dependencies", 
        #    "--profile", f"./external/profiles/{os_type_str}_debug.profile",
        #    "--settings", "build_type=Debug"  
        #], check=True)
        
        # Install dependencies for Release build
        subprocess.run([
            "conan", "install", ".", 
            "--build=missing", 
            "--output-folder=./dependencies", 
            "--profile", f"./external/profiles/{os_type_str}_release.profile",
            "--settings", "build_type=Release" 
        ], check=True)
        
        print(f"Conan installation completed successfully for {os_type_str}.")
    
    except subprocess.CalledProcessError as e:
        print(f"Error running Conan: {e}")
        exit(1)  # Ensure script stops on error

if __name__ == "__main__":
    system_name = platform.system().lower()  # More accurate OS detection
    
    if system_name == "windows":
        run_conan("win")
    elif system_name in ["linux", "darwin"]:  # Darwin is macOS
        run_conan("unix")
    else:
        print("Unsupported OS detected!")
        exit(1)
